import json
from datetime import datetime, timedelta
import ipaddress
import pandas as pd
import itertools
from operator import itemgetter



# --- Helper Functions ---

def remap_activity_type(login_types):
    """Remaps a set of raw login types to standardized categories."""
    remapped_types = set()
    for t in login_types:
        if not t:
            continue
        if 'NETWORK' in t:
            remapped_types.add('NETWORK')
        elif 'INTERACTIVE' in t:
            remapped_types.add('RDP/Interactive')
        elif 'UNLOCK' in t:
            remapped_types.add('UNLOCK')
        else:
            remapped_types.add(t)  # Keep any other types as is
    return ', '.join(sorted(list(remapped_types)))


def is_informative_ip(ip_str):
    """
    Checks if an IP address is a public or private address, not a loopback or unspecified one.
    """
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_loopback or ip.is_unspecified)
    except ValueError:
        return False


def format_duration(seconds):
    """
    Formats duration in seconds into an hh:mm:ss string.
    Handles negative durations.
    """
    if seconds is None or not isinstance(seconds, (int, float)):
        return ''
    if seconds < 0:
        sign = "-"
        seconds = abs(seconds)
    else:
        sign = ""

    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{sign}{int(h):02d}:{int(m):02d}:{int(s):02d}"


def to_datetime(time_str):
    """Converts a time string to a datetime object, handling empty strings."""
    if not time_str:
        return None
    return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S.%f')


# --- Main Correlation Logic ---

def correlate_login_logout(data):
    """
    Pass 1 & 2: Normalizes, aggregates, and correlates login/logout events.
    """
    pql_rows = data['pql_rows']
    SYSTEM_USER_PREFIXES = ['DWM-', 'UMFD-']

    def is_system_user(username):
        if not username: return False
        return any(username.startswith(prefix) for prefix in SYSTEM_USER_PREFIXES)

    for row in pql_rows:
        row['username'] = row.get('event_login_userName') or row.get('event_logout_tgt_user_name')
        row['event_time_dt'] = datetime.strptime(row['event_time'], '%Y-%m-%d %H:%M:%S.%f')

    pql_rows.sort(key=lambda x: x['event_time_dt'])
    login_events = [r for r in pql_rows if r['event_type'] == 'Login']
    logout_events = [r for r in pql_rows if r['event_type'] == 'Logout']

    saved_logins = []
    if login_events:
        for event in login_events:
            if not saved_logins or not event.get('event_login_loginIsSuccessful'):
                saved_logins.append({'event_time': event['event_time_dt'], 'endpoint_name': event.get('endpoint_name'),
                                     'event_login_isAdministratorEquivalent': event.get(
                                         'event_login_isAdministratorEquivalent', False),
                                     'event_login_loginIsSuccessful': event.get('event_login_loginIsSuccessful', False),
                                     'event_login_type': {event.get('event_login_type')}, 'username': event['username'],
                                     'src_endpoint_ip_address': event.get('src_endpoint_ip_address'),
                                     'login_time_list': [event['event_time_dt']]})
                continue

            last_login = saved_logins[-1]
            time_diff = (event['event_time_dt'] - last_login['login_time_list'][-1]).total_seconds()

            # <<< FIX: Added check for matching endpoint_name
            same_system = last_login.get('endpoint_name') == event.get('endpoint_name')

            is_current_user_system = is_system_user(event['username'])
            is_last_user_system = is_system_user(last_login['username'])
            same_real_user = (
                        not is_current_user_system and not is_last_user_system and event['username'] == last_login[
                    'username'])

            should_merge = False
            if time_diff <= 120 and same_system:  # <<< FIX: Enforce same system for all merges
                if is_current_user_system or same_real_user:
                    should_merge = True
                elif is_last_user_system:
                    last_login['username'] = event['username']
                    should_merge = True

            if should_merge:
                last_login['login_time_list'].append(event['event_time_dt'])
                last_login['event_login_isAdministratorEquivalent'] = last_login.get(
                    'event_login_isAdministratorEquivalent') or event.get('event_login_isAdministratorEquivalent')
                last_login['event_login_type'].add(event.get('event_login_type'))
                if is_informative_ip(event.get('src_endpoint_ip_address')) and not is_informative_ip(
                        last_login.get('src_endpoint_ip_address')):
                    last_login['src_endpoint_ip_address'] = event.get('src_endpoint_ip_address')
            else:
                saved_logins.append({'event_time': event['event_time_dt'], 'endpoint_name': event.get('endpoint_name'),
                                     'event_login_isAdministratorEquivalent': event.get(
                                         'event_login_isAdministratorEquivalent', False),
                                     'event_login_loginIsSuccessful': event.get('event_login_loginIsSuccessful', False),
                                     'event_login_type': {event.get('event_login_type')}, 'username': event['username'],
                                     'src_endpoint_ip_address': event.get('src_endpoint_ip_address'),
                                     'login_time_list': [event['event_time_dt']]})

    saved_logouts = []
    if logout_events:
        logout_events.sort(key=lambda x: x['event_time_dt'], reverse=True)
        for event in logout_events:
            if not saved_logouts:
                saved_logouts.append({'event_time': event['event_time_dt'], 'username': event['username'],
                                      'endpoint_name': event.get('endpoint_name'),
                                      'logout_time_list': [event['event_time_dt']], 'paired': False})
                continue

            last_logout = saved_logouts[-1]
            time_diff = (last_logout['logout_time_list'][-1] - event['event_time_dt']).total_seconds()

            # <<< FIX: Added check for matching username AND endpoint_name
            if event['username'] == last_logout['username'] and event.get('endpoint_name') == last_logout.get(
                    'endpoint_name') and time_diff < 120:
                last_logout['logout_time_list'].append(event['event_time_dt'])
                last_logout['event_time'] = max(last_logout['event_time'], event['event_time_dt'])
            else:
                saved_logouts.append({'event_time': event['event_time_dt'], 'username': event['username'],
                                      'endpoint_name': event.get('endpoint_name'),
                                      'logout_time_list': [event['event_time_dt']], 'paired': False})
        saved_logouts.sort(key=lambda x: x['event_time'])

    final_events = []
    for login in saved_logins:
        if is_system_user(login['username']): continue
        found_pair = False
        for logout in saved_logouts:
            # <<< FIX: Added check for matching endpoint_name in pairing logic
            if not logout['paired'] and login['username'] == logout['username'] and login.get(
                    'endpoint_name') == logout.get('endpoint_name') and login['event_time'] < logout['event_time']:
                duration_sec = (logout['event_time'] - login['event_time']).total_seconds()
                final_events.append({'login_time': login['event_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:23],
                                     'logout_time': logout['event_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:23],
                                     'remote_logon': is_informative_ip(login.get('src_endpoint_ip_address')),
                                     'login_types': ','.join(filter(None, login['event_login_type'])),
                                     'source_IP': login.get('src_endpoint_ip_address'),
                                     'dst_system': login.get('endpoint_name'), 'user': login['username'],
                                     'login_successful': login['event_login_loginIsSuccessful'],
                                     'duration_s': round(duration_sec, 3),
                                     'duration_s': round(duration_sec, 3),
                                     'duration': format_duration(duration_sec),
                                     'privileged': login['event_login_isAdministratorEquivalent']})
                logout['paired'] = True
                found_pair = True
                break
        if not found_pair:
            final_events.append(
                {'login_time': login['event_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:23], 'logout_time': '',
                 'remote_logon': is_informative_ip(login.get('src_endpoint_ip_address')),
                 'login_types': ','.join(filter(None, login['event_login_type'])),
                 'source_IP': login.get('src_endpoint_ip_address'), 'dst_system': login.get('endpoint_name'),
                 'user': login['username'], 'login_successful': login['event_login_loginIsSuccessful'],
                 'duration_s': '', 'duration': '',
                 'privileged': login['event_login_isAdministratorEquivalent']})

    for logout in saved_logouts:
        if not logout['paired'] and not is_system_user(logout['username']):
            final_events.append(
                {'login_time': '', 'logout_time': logout['event_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:23],
                 'remote_logon': False, 'login_types': '', 'source_IP': '', 'dst_system': logout.get('endpoint_name'),
                 'user': logout['username'], 'login_successful': '', 'duration_s': '', 'duration': '',
                 'privileged': ''})

    final_events.sort(key=lambda x: x['login_time'] or x['logout_time'])
    return final_events


def collapse_orphans(events, threshold_minutes=30):
    """
    Pass 3: Collapses orphan logins/logouts into adjacent sessions.
    """
    if not events: return []
    threshold = timedelta(minutes=threshold_minutes)

    processed_events = []
    for current_event in events:
        is_orphan_logout = bool(current_event['logout_time'] and not current_event['login_time'])
        if is_orphan_logout and processed_events:
            last_event = processed_events[-1]
            is_previous_session_complete = bool(last_event['login_time'] and last_event['logout_time'])

            # <<< FIX: Added check for matching dst_system
            if is_previous_session_complete and last_event['user'] == current_event['user'] and last_event[
                'dst_system'] == current_event['dst_system']:
                last_logout_time = to_datetime(last_event['logout_time'])
                current_logout_time = to_datetime(current_event['logout_time'])
                if current_logout_time and last_logout_time and (current_logout_time - last_logout_time) <= threshold:
                    last_event['logout_time'] = current_event['logout_time']
                    new_duration_sec = (to_datetime(last_event['logout_time']) - to_datetime(
                        last_event['login_time'])).total_seconds()
                    last_event['duration_s'] = round(new_duration_sec, 3)
                    last_event['duration'] = format_duration(new_duration_sec)
                    continue
        processed_events.append(current_event)

    final_events = []
    reversed_list = processed_events[::-1]
    for current_event in reversed_list:
        is_orphan_login = bool(current_event['login_time'] and not current_event['logout_time'])
        if is_orphan_login and final_events:
            next_event = final_events[-1]
            is_next_session_complete = bool(next_event['login_time'] and next_event['logout_time'])

            # <<< FIX: Added check for matching dst_system
            if is_next_session_complete and next_event['user'] == current_event['user'] and next_event['dst_system'] == \
                    current_event['dst_system']:
                next_login_time = to_datetime(next_event['login_time'])
                current_login_time = to_datetime(current_event['login_time'])
                if next_login_time and current_login_time and (next_login_time - current_login_time) <= threshold:
                    next_event['login_time'] = current_event['login_time']
                    new_duration_sec = (to_datetime(next_event['logout_time']) - to_datetime(
                        next_event['login_time'])).total_seconds()
                    next_event['duration_s'] = round(new_duration_sec, 3)
                    next_event['duration'] = format_duration(new_duration_sec)
                    next_event['remote_logon'] = current_event['remote_logon'] or next_event['remote_logon']
                    next_event['source_IP'] = current_event['source_IP'] or next_event['source_IP']
                    continue
        final_events.append(current_event)

    return final_events[::-1]


def generate_activity_summary(events, consolidation_threshold_hours=3, buffer_minutes=10, group_by_source_ip=True):
    """
    Analyzes sessions to produce a consolidated activity summary using standard Python objects.
    """
    # Filter for complete sessions first
    sessions = [e for e in events if e.get('login_time') and e.get('logout_time')]

    # Conditionally filter for informative IPs if grouping by them
    if group_by_source_ip:
        sessions = [s for s in sessions if is_informative_ip(s.get('source_IP'))]

    if not sessions:
        return []  # Return an empty list if no valid sessions

    # Add datetime objects to each session for calculations
    for s in sessions:
        s['dst_system'] = s.get('dst_system') or 'Unknown System'  # Ensure dst_system is not None
        s['login_dt'] = to_datetime(s['login_time'])
        s['logout_dt'] = to_datetime(s['logout_time'])

    # Define the keys for sorting and grouping
    grouping_keys = ['user', 'dst_system']
    if group_by_source_ip:
        grouping_keys.append('source_IP')

    # Sort the data to prepare for itertools.groupby
    sessions.sort(key=itemgetter(*grouping_keys, 'login_dt'))

    consolidation_threshold = timedelta(hours=consolidation_threshold_hours)
    buffer = timedelta(minutes=buffer_minutes)
    consolidated_windows = []

    # Group sessions by the defined keys
    for key_tuple, group_iterator in itertools.groupby(sessions, key=itemgetter(*grouping_keys)):
        group = list(group_iterator)
        if not group:
            continue

        # Unpack the group keys
        user, dst_system = key_tuple[0], key_tuple[1]
        source_ip = key_tuple[2] if group_by_source_ip else ''

        # Consolidate time windows within the group
        first_session = group[0]
        current_start = first_session['login_dt']
        current_end = first_session['logout_dt']
        current_login_types = set(first_session['login_types'].split(','))

        for i in range(1, len(group)):
            next_session = group[i]
            gap = next_session['login_dt'] - current_end

            if gap <= consolidation_threshold:
                current_end = max(current_end, next_session['logout_dt'])
                current_login_types.update(next_session['login_types'].split(','))
            else:
                # Finish the previous window
                duration = current_end - current_start
                source_ips_str = source_ip if group_by_source_ip else ', '.join(
                    sorted([ip for ip in {s['source_IP'] for s in group} if is_informative_ip(ip)]))

                consolidated_windows.append({
                    'Date': current_start.strftime('%Y-%m-%d'), 'user': user, 'source_IP': source_ips_str,
                    'dst_system': dst_system,
                    f'earliest_activity': (current_start - buffer).strftime(
                        '%Y-%m-%d %H:%M:%S'),
                    f'latest_activity': (current_end + buffer).strftime('%Y-%m-%d %H:%M:%S'),
                    'duration_s': round(duration.total_seconds()),
                    'duration': format_duration(duration.total_seconds()),
                    'activity_type': remap_activity_type(current_login_types)
                })
                # Start a new window
                current_start = next_session['login_dt']
                current_end = next_session['logout_dt']
                current_login_types = set(next_session['login_types'].split(','))

        # Add the last processed window for the group
        duration = current_end - current_start
        source_ips_str = source_ip if group_by_source_ip else ', '.join(
            sorted([ip for ip in {s['source_IP'] for s in group} if is_informative_ip(ip)]))

        consolidated_windows.append({
            'Date': current_start.strftime('%Y-%m-%d'), 'user': user, 'source_IP': source_ips_str,
            'dst_system': dst_system,
            f'earliest_activity': (current_start - buffer).strftime('%Y-%m-%d %H:%M:%S'),
            f'latest_activity': (current_end + buffer).strftime('%Y-%m-%d %H:%M:%S'),
            'duration_s': round(duration.total_seconds()),
            'duration': format_duration(duration.total_seconds()),
            'activity_type': remap_activity_type(current_login_types)
        })

    return consolidated_windows

# --- Execution ---
if __name__ == '__main__':
    pass
    # Configuration
    SHOW_INTERMEDIATE_TABLES = True # Set to False to hide intermediate steps
    CONSOLIDATION_THRESHOLD_HOURS = 3
    BUFFER_MINUTES = 10

    # 1. Run the initial correlation (Pass 1 and 2)
    data = json_data
    correlated_events = correlate_login_logout(data)

    if SHOW_INTERMEDIATE_TABLES:
        print("### Results After Initial Correlation (Pass 1 & 2) ###")
        print(pd.DataFrame(correlated_events).to_markdown(index=False))
        print("\n" + "=" * 50 + "\n")

    # 2. Run the orphan collapsing pass (Pass 3)
    final_correlated_events = collapse_orphans(correlated_events, threshold_minutes=30)

    if SHOW_INTERMEDIATE_TABLES:
        print("### Results After Collapsing Orphans (Pass 3) ###")
        print(pd.DataFrame(final_correlated_events).to_markdown(index=False))
        print("\n" + "=" * 50 + "\n")


    # 3. Generate and print the final activity summary
    summary_list_grouped = generate_activity_summary(final_correlated_events, consolidation_threshold_hours=CONSOLIDATION_THRESHOLD_HOURS, buffer_minutes=BUFFER_MINUTES,group_by_source_ip=True)


    # 4. Print the final summary table
    if summary_list_grouped:
        print("### User Activity Timeframe Summary (Grouped by Source IP) ###")
        summary_df = pd.DataFrame(summary_list_grouped)

        # Define columns for sorting and ordering
        earliest_col_name = f'earliest_activity'
        final_column_order = [
            'Date', 'user', 'source_IP', 'dst_system', earliest_col_name,
            f'latest_activity', 'duration_s',
            'duration', 'activity_type'
        ]

        # Sort and reorder columns for display
        summary_df = summary_df[final_column_order].sort_values(by=earliest_col_name).reset_index(drop=True)
        print(summary_df.to_markdown(index=False))
    else:
        print("\nNo consolidated activity to display.")
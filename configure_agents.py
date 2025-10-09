import os
import uuid
import shutil

# --- Configuration ---
SOURCE_DIR = 'agents'
DEPLOYMENT_DIR = 'deployment'
ZIP_NAME = 'deployment_package'
DB_MANAGER_FILENAME = 'DB_Manager.json'

def get_console_input():
    """Prompts the user for the console name and sanitizes it."""
    console_input = input("➡️ Enter the console name (e.g., 'euce1-103' or 'euce1-103.sentinelone.net'): ").strip()
    if not console_input:
        print("❌ Console name cannot be empty. Exiting.")
        return None
    
    # Remove .sentinelone.net if the user included it
    suffix_to_remove = ".sentinelone.net"
    if console_input.endswith(suffix_to_remove):
        console_name = console_input[:-len(suffix_to_remove)]
    else:
        console_name = console_input
    
    print(f"✅ Using console name for replacement: {console_name}")
    return console_name

def find_json_files(source_directory):
    """Scans the source directory to find all JSON files and the DB Manager file."""
    json_files = []
    db_manager_path = None
    for root, _, files in os.walk(source_directory):
        for file in files:
            if file.endswith('.json'):
                full_path = os.path.join(root, file)
                json_files.append(full_path)
                if file == DB_MANAGER_FILENAME:
                    db_manager_path = full_path
    
    if not db_manager_path:
        print(f"❌ Critical error: '{DB_MANAGER_FILENAME}' not found. Exiting.")
        return None, None

    print(f"✅ Found {len(json_files)} JSON files to process.")
    return json_files, db_manager_path

def setup_deployment_directory(directory):
    """Creates a clean deployment directory."""
    print(f"⚙️  Setting up the '{directory}' directory...")
    if os.path.exists(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)

def process_agent_files(json_files, db_manager_uuid, console_name, deployment_dir):
    """
    Processes each JSON file to replace placeholders and saves it to the deployment directory.
    Returns a list of tuples mapping agent names to their generated UUIDs.
    """
    uuid_mappings = []
    for file_path in json_files:
        try:
            file_name = os.path.basename(file_path)
            
            # The DB Manager's own <UUID> is its special UUID. Others get a new one.
            agent_uuid = db_manager_uuid if file_name == DB_MANAGER_FILENAME else str(uuid.uuid4())

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Replace all three placeholders
            content = content.replace('<UUID>', agent_uuid)
            content = content.replace('<DB_UUID>', db_manager_uuid)
            content = content.replace('<CONSOLE_NAME>', console_name)

            # Save the modified file
            new_file_path = os.path.join(deployment_dir, file_name)
            with open(new_file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            # Store the mapping for the final report
            agent_name = os.path.splitext(file_name)[0].replace('_', ' ')
            uuid_mappings.append((agent_name, agent_uuid))

        except Exception as e:
            print(f"⚠️  Could not process file {file_path}: {e}")
    
    return uuid_mappings

def create_archive_and_cleanup(zip_filename, source_dir):
    """Creates a zip archive from the source directory and then removes the directory."""
    print(f"\n📦 Creating zip archive: '{zip_filename}.zip'...")
    shutil.make_archive(zip_filename, 'zip', source_dir)
    print(f"🎉 Deployment package '{zip_filename}.zip' is ready!")
    
    print(f"🧹 Cleaning up the '{source_dir}' directory...")
    shutil.rmtree(source_dir)

def print_summary_report(mappings):
    """Prints a summary table of the UUIDs assigned to each agent."""
    print("\n--- Agent <UUID> Assignment Summary ---")
    print("| {:<25} | {:<36} |".format("Agent Name", "UUID"))
    print("|-" + "-"*25 + "|-" + "-"*36 + "|")
    # Sort for consistent, readable output
    for name, uid in sorted(mappings, key=lambda x: x[0]):
        print(f"| {name:<25} | {uid:<36} |")
    print("---------------------------------------------------------------")

def main():
    """Main function to orchestrate the deployment package creation."""
    console_name = get_console_input()
    if not console_name:
        return

    json_files, db_manager_path = find_json_files(SOURCE_DIR)
    if not db_manager_path:
        return

    # Generate the special UUID for the DB Manager, which is needed by other agents
    db_manager_uuid = str(uuid.uuid4())
    print(f"🔑 Generated special UUID for DB Manager: {db_manager_uuid}")

    setup_deployment_directory(DEPLOYMENT_DIR)
    
    uuid_mappings = process_agent_files(json_files, db_manager_uuid, console_name, DEPLOYMENT_DIR)

    if not uuid_mappings:
        print("❌ No files were processed. Halting.")
        return

    create_archive_and_cleanup(ZIP_NAME, DEPLOYMENT_DIR)
    print_summary_report(uuid_mappings)

if __name__ == '__main__':
    main()



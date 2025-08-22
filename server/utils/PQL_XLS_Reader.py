import pandas as pd
import os


class PQL_XLS_Reader:
    """
    Reads PQL-related information from different sheets of an Excel file
    and generates a structured prompt for natural language to PQL conversion.
    """

    # Define expected sheet names as constants
    SHEET_SDL_FIELDS = "sdl_fields"
    SHEET_SYNTAX_COMMANDS = "pql_syntax_commands"
    SHEET_SYNTAX_FILTERS = "pql_syntax_filters"
    SHEET_QUERY_EXAMPLES = "query_examples"
    SHEET_BEHAVIOURAL_INDICATORS = "Behavioural Indicators"

    def __init__(self, excel_file_path: str):
        """
        Initializes the reader by loading data from the specified Excel file.

        Args:
            excel_file_path (str): The path to the Excel file.

        Raises:
            FileNotFoundError: If the Excel file cannot be found.
            ValueError: If a required sheet is missing or data cannot be loaded.
        """
        if not os.path.exists(excel_file_path):
            raise FileNotFoundError(f"Error: Excel file not found at {excel_file_path}")

        self.excel_file_path = excel_file_path
        self.data = {}

        try:
            xls = pd.ExcelFile(excel_file_path)

            sheet_map = {
                self.SHEET_SDL_FIELDS: "df_fields",
                self.SHEET_SYNTAX_COMMANDS: "df_commands",
                self.SHEET_SYNTAX_FILTERS: "df_filters",
                self.SHEET_QUERY_EXAMPLES: "df_examples",
                self.SHEET_BEHAVIOURAL_INDICATORS: "df_indicators"
            }

            for sheet_name_const, df_attr_name in sheet_map.items():
                actual_sheet_name = None
                for s_name in xls.sheet_names:
                    if s_name.lower() == sheet_name_const.lower():
                        actual_sheet_name = s_name
                        break

                if actual_sheet_name:
                    self.data[df_attr_name] = pd.read_excel(xls, sheet_name=actual_sheet_name)
                    self.data[df_attr_name] = self.data[df_attr_name].fillna('')
                else:
                    print(
                        f"Warning: Sheet '{sheet_name_const}' not found in {excel_file_path}. This section will be empty.")
                    self.data[df_attr_name] = pd.DataFrame()
        except Exception as e:
            raise ValueError(f"Error reading Excel file '{excel_file_path}': {e}")

    def _format_sdl_fields(self) -> str:
        df = self.data.get("df_fields", pd.DataFrame())
        if df.empty or not all(col in df.columns for col in ["Field", "Description"]):
            if not df.empty:
                print(f"Warning: Missing 'Field' or 'Description' columns in '{self.SHEET_SDL_FIELDS}' sheet.")
            return "[PQL Fields Reference]\n(No data available or sheet/columns missing)\n\n"

        content = ["[PQL Fields Reference]"]
        for _, row in df.iterrows():
            content.append(f"- Field: {row.get('Field', 'N/A')}")
            content.append(f"- Description: {row.get('Description', 'N/A')}")
            content.append("")
        return "\n".join(content) + "\n"

    def _format_syntax_commands(self) -> str:
        df = self.data.get("df_commands", pd.DataFrame())
        required_cols = ["Category", "Command", "Description", "Syntax", "Example"]
        if df.empty or not all(col in df.columns for col in required_cols):
            if not df.empty:
                print(f"Warning: Missing one or more of {required_cols} in '{self.SHEET_SYNTAX_COMMANDS}' sheet.")
            return "[PQL Syntax Commands Reference]\n(No data available or sheet/columns missing)\n\n"

        content = ["[PQL Syntax Commands Reference]"]
        for _, row in df.iterrows():
            content.append(f"- Category: {row.get('Category', 'N/A')}")
            content.append(f"- Command: {row.get('Command', 'N/A')}")
            content.append(f"- Description: {row.get('Description', 'N/A')}")
            content.append(f"- Syntax: {row.get('Syntax', 'N/A')}")
            content.append(f"- Example: {row.get('Example', 'N/A')}")
            content.append("")
        return "\n".join(content) + "\n"

    def _format_syntax_filters(self) -> str:
        df = self.data.get("df_filters", pd.DataFrame())
        # User's script expects "Command" column for filter name
        required_cols = ["Command", "Description", "Syntax", "Example"]
        if df.empty or not all(col in df.columns for col in required_cols):
            if not df.empty:
                print(f"Warning: Missing one or more of {required_cols} in '{self.SHEET_SYNTAX_FILTERS}' sheet.")
            return "[PQL Syntax Filters Reference]\n(No data available or sheet/columns missing)\n\n"

        content = ["[PQL Syntax Filters Reference]"]
        for _, row in df.iterrows():
            content.append(f"Filter: {row.get('Command', 'N/A')}")  # Uses 'Command' column for filter name
            content.append(f"Description: {row.get('Description', 'N/A')}")
            content.append(f"Syntax: {row.get('Syntax', 'N/A')}")
            content.append(f"Example: {row.get('Example', 'N/A')}")
            content.append("")
        return "\n".join(content) + "\n"

    def _format_query_examples(self) -> str:
        df = self.data.get("df_examples", pd.DataFrame())
        desc_col = "Description/Purpose"
        query_col = "Query"

        if desc_col not in df.columns and "Description" in df.columns:
            desc_col = "Description"

        if df.empty or not all(col in df.columns for col in [desc_col, query_col]):
            if not df.empty:
                print(f"Warning: Missing '{desc_col}' or '{query_col}' columns in '{self.SHEET_QUERY_EXAMPLES}' sheet.")
            return "[PQL Query Examples]\n(No data available or sheet/columns missing)\n\n"

        content = ["[PQL Query Examples]"]
        for _, row in df.iterrows():
            content.append(f"Description/Purpose: {row.get(desc_col, 'N/A')}")
            content.append(f"Query: {row.get(query_col, 'N/A')}")
            content.append("")
        return "\n".join(content) + "\n"

    def _format_behavioural_indicators(self) -> str:
        df = self.data.get("df_indicators", pd.DataFrame())
        required_cols = ["Mitre IDs", "indicator.name", "Description"]
        if df.empty or not all(col in df.columns for col in required_cols):
            if not df.empty:
                print(
                    f"Warning: Missing one or more of {required_cols} in '{self.SHEET_BEHAVIOURAL_INDICATORS}' sheet.")
            return "[PQL Behavioral Indicators Reference]\n(No data available or sheet/columns missing)\n\n"

        content = ["[PQL Behavioral Indicators Reference]"]
        for _, row in df.iterrows():
            content.append(f"Mitre IDs: {row.get('Mitre IDs', 'N/A')}")
            content.append(f"indicator.name: {row.get('indicator.name', 'N/A')}")
            content.append(f"Description: {row.get('Description', 'N/A')}")
            content.append("")
        return "\n".join(content) + "\n"

    def generate_prompt(self, write_to_disk: bool = False) -> str:
        """
        Generates the full prompt string using data from the Excel sheets
        and prints size analysis of each section.

        Args:
            write_to_disk (bool, optional): If True, writes the prompt to
                                             'NL2PQL_prompt.txt' in the same
                                             directory as the Excel file.
                                             Defaults to False.

        Returns:
            str: The generated prompt string.
        """
        section_contents = {}
        section_metrics = []  # Stores (name, char_len, byte_len)

        # --- Section Content Generation and Metrics ---
        sdl_fields_content = self._format_sdl_fields()
        section_contents["sdl_fields"] = sdl_fields_content
        section_metrics.append((
            "[PQL Fields Reference]",
            len(sdl_fields_content),
            len(sdl_fields_content.encode('utf-8'))
        ))

        syntax_commands_content = self._format_syntax_commands()
        section_contents["syntax_commands"] = syntax_commands_content
        section_metrics.append((
            "[PQL Syntax Commands Reference]",
            len(syntax_commands_content),
            len(syntax_commands_content.encode('utf-8'))
        ))

        syntax_filters_content = self._format_syntax_filters()
        section_contents["syntax_filters"] = syntax_filters_content
        section_metrics.append((
            "[PQL Syntax Filters Reference]",
            len(syntax_filters_content),
            len(syntax_filters_content.encode('utf-8'))
        ))

        query_examples_content = self._format_query_examples()
        section_contents["query_examples"] = query_examples_content
        section_metrics.append((
            "[PQL Query Examples]",
            len(query_examples_content),
            len(query_examples_content.encode('utf-8'))
        ))

        behavioural_indicators_content = self._format_behavioural_indicators()
        section_contents["behavioural_indicators"] = behavioural_indicators_content
        section_metrics.append((
            "[PQL Behavioral Indicators Reference]",
            len(behavioural_indicators_content),
            len(behavioural_indicators_content.encode('utf-8'))
        ))

        # --- Assemble Full Prompt ---
        prompt_header = "Here are examples of how PowerQuery (PQL) queries are created for security-related data analysis"
        guidance_begin = "====BEGIN NATURAL_LANGUAGE TO PQL QUERY GUIDANCE====="
        guidance_end = "====END NATURAL_LANGUAGE TO PQL QUERY GUIDANCE====="
        prompt_footer = "Now, based on the user's input, translate the natural language request into an appropriate PQL query. Remember that in PQL the columns in the output need to be explicitly mentioned. Always include them."

        full_prompt_parts = [
            prompt_header,
            guidance_begin,
            section_contents["sdl_fields"],
            section_contents["syntax_commands"],
            section_contents["syntax_filters"],
            section_contents["query_examples"],
            section_contents["behavioural_indicators"],
            guidance_end,
            prompt_footer
        ]
        full_prompt = "\n".join(full_prompt_parts)

        # --- Print Section Size Analysis ---
        print("\n--- Prompt Section Size Analysis ---")
        if not section_metrics:
            print("No sections generated or analyzed.")
        else:
            # Sort by byte length to find the largest
            sorted_by_byte_len = sorted(section_metrics, key=lambda x: x[2], reverse=True)

            total_chars = 0
            total_bytes = 0

            for name, char_len, byte_len in section_metrics:  # Use original order for printing details
                kb_size = byte_len / 1024.0
                print(f"Section: \"{name}\"")
                print(f"  Characters: {char_len}")
                print(f"  Size: {byte_len} bytes ({kb_size:.2f} KB)")
                total_chars += char_len
                total_bytes += byte_len

            if sorted_by_byte_len:
                largest_section_name, largest_char_len, largest_byte_len = sorted_by_byte_len[0]
                largest_kb = largest_byte_len / 1024.0
                print(f"\nLargest section by content size: \"{largest_section_name}\"")
                print(f"  Characters: {largest_char_len}")
                print(f"  Size: {largest_byte_len} bytes ({largest_kb:.2f} KB)")

            total_prompt_chars = len(full_prompt)
            total_prompt_bytes = len(full_prompt.encode('utf-8'))
            total_prompt_kb = total_prompt_bytes / 1024.0
            print(
                f"\nTotal for all generated sections: {total_chars} characters, {total_bytes} bytes ({total_bytes / 1024.0:.2f} KB)")
            print(
                f"Total full prompt size: {total_prompt_chars} characters, {total_prompt_bytes} bytes ({total_prompt_kb:.2f} KB)")
            print("--- End of Size Analysis ---")

        if write_to_disk:
            output_dir = os.path.dirname(self.excel_file_path)
            if not output_dir:
                output_dir = "."
            output_file_path = os.path.join(output_dir, "NL2PQL_prompt.txt")
            try:
                with open(output_file_path, "w", encoding="utf-8") as f:
                    f.write(full_prompt)
                print(f"\nPrompt successfully written to: {output_file_path}")
            except IOError as e:
                print(f"\nError writing prompt to disk: {e}")

        return full_prompt




if __name__ == '__main__':
    dummy_excel_file = "rag_pql_queries_dummy.xlsx"
    try:
        with pd.ExcelWriter(dummy_excel_file) as writer:
            pd.DataFrame({
                'Field': ['ProcessId', 'FileName', 'CommandLine', 'ParentProcessId', 'UserId'],
                'Description': ['The ID of the process', 'Name of the file accessed',
                                'The command line of the process', 'ID of the parent process',
                                'User associated with event']
            }).to_excel(writer, sheet_name=PQL_XLS_Reader.SHEET_SDL_FIELDS, index=False)

            pd.DataFrame({
                'Category': ['Aggregation', 'Filtering', 'Projection', 'Sorting', 'Limiting'],
                'Command': ['summarize', 'where', 'project', 'order by', 'limit'],
                'Description': ['Groups rows that have the same values', 'Filters rows based on a condition',
                                'Selects columns to include', 'Sorts rows by specified columns',
                                'Restricts the number of rows returned'],
                'Syntax': ['summarize by <field>', 'where <condition>', 'project <col1>, <col2>',
                           'order by <field> [asc|desc]', 'limit <number>'],
                'Example': ['summarize count() by UserName', 'where EventType == "Login"',
                            'project Timestamp, UserName, Action',
                            'order by Timestamp desc', 'limit 100']
            }).to_excel(writer, sheet_name=PQL_XLS_Reader.SHEET_SYNTAX_COMMANDS, index=False)

            # Updated 'Command' column for filters to match user's script logic in _format_syntax_filters
            pd.DataFrame({
                'Command': ['contains', 'startswith', 'endswith', '==', '!='],  # Was 'Filter', now 'Command'
                'Description': ['Checks if string contains substring', 'Checks if string starts with prefix',
                                'Checks if string ends with suffix', 'Equals comparison', 'Not equals comparison'],
                'Syntax': ['<field> contains "value"', '<field> startswith "prefix"', '<field> endswith "suffix"',
                           '<field> == "value"', '<field> != "value"'],
                'Example': ['FileName contains "malware"', 'ProcessName startswith "exploit"',
                            'FilePath endswith ".dll"',
                            'EventType == "FileDelete"', 'UserName != "system"']
            }).to_excel(writer, sheet_name=PQL_XLS_Reader.SHEET_SYNTAX_FILTERS, index=False)

            pd.DataFrame({
                'Description/Purpose': ['Find all notepad processes', 'Count logon events by user',
                                        'Recent 10 file modifications',
                                        'PowerShell execution from non-standard paths',
                                        'Processes created by Word or Excel'],
                'Query': ['DeviceProcessEvents | where ProcessName == "notepad.exe"',
                          'SecurityAlert | where AlertName == "User Logon" | summarize count() by UserName',
                          'DeviceFileEvents | where ActionType == "FileModified" | order by Timestamp desc | limit 10',
                          'DeviceProcessEvents | where ProcessName == "powershell.exe" and not (FolderPath contains "System32" or FolderPath contains "SysWOW64") | project Timestamp, FileName, CommandLine',
                          'DeviceProcessEvents | where ParentProcessName in ("winword.exe", "excel.exe") | project Timestamp, ParentProcessName, ProcessName, CommandLine']
            }).to_excel(writer, sheet_name=PQL_XLS_Reader.SHEET_QUERY_EXAMPLES, index=False)

            pd.DataFrame({
                'Mitre IDs': ['T1059.001', 'T1003', 'T1057', 'T1047', 'T1547.001'],
                'indicator.name': ['PowerShell Execution', 'OS Credential Dumping', 'Process Discovery',
                                   'Windows Management Instrumentation', 'Registry Run Keys / Startup Folder'],
                'Description': [
                    'Adversaries may abuse PowerShell commands and scripts for execution.',
                    'Adversaries may attempt to dump credentials to obtain account login and credential material.',
                    'Adversaries may attempt to get information about running processes on a system.',
                    'Adversaries may abuse WMI to execute malicious commands and payloads.',
                    'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.'
                ]
            }).to_excel(writer, sheet_name=PQL_XLS_Reader.SHEET_BEHAVIOURAL_INDICATORS, index=False)

        print(f"Created/Updated dummy Excel file: {dummy_excel_file} (with more sample data)")

        try:
            reader = PQL_XLS_Reader(dummy_excel_file)
            # reader = PQL_XLS_Reader("../resources/rag_pql_queries.xlsx")

            prompt_content_no_write = reader.generate_prompt()
            print("\n--- Generated Prompt Snippet (not written to disk) ---")
            print(prompt_content_no_write[:1000] + "\n...")

            # Generate the prompt and write it to disk (will also print size analysis again)
            # prompt_content_with_write = reader.generate_prompt(write_to_disk=True)

            print(f"\nTo test with your actual file, change '{dummy_excel_file}' to your file's path in the script.")
            print(
                f"The dummy Excel file '{dummy_excel_file}' was created/updated for testing. You can inspect or delete it.")

        except (FileNotFoundError, ValueError) as e:
            print(e)

    except Exception as e_main:
        print(f"An error occurred during the setup or execution: {e_main}")
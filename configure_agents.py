import os
import uuid
import shutil

# --- Configuration ---
SOURCE_DIR = 'agents'
DEPLOYMENT_DIR = 'deployment'
ZIP_NAME = 'deployment_package'

def create_deployment_package():
    """
    Finds agent JSON files, replaces UUID placeholders, creates new files
    in a deployment directory, zips the contents, and reports the results.
    """
    # 1. Create a new, empty deployment folder
    print(f"⚙️  Setting up the '{DEPLOYMENT_DIR}' directory...")
    if os.path.exists(DEPLOYMENT_DIR):
        shutil.rmtree(DEPLOYMENT_DIR)
    os.makedirs(DEPLOYMENT_DIR)

    json_files = []
    # 2. Recursively scan the source folder for JSON files
    for root, _, files in os.walk(SOURCE_DIR):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))

    print(f"✅ Found {len(json_files)} JSON files to process.")
    
    uuid_mappings = []

    # 3 & 4. Process each JSON file
    for file_path in json_files:
        # Generate a single unique UUID for this file
        new_uuid = str(uuid.uuid4())
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Replace all instances of the placeholder with the new UUID
            updated_content = content.replace('<UUID>', new_uuid)

            # Create the new file inside the deployment folder
            file_name = os.path.basename(file_path)
            new_file_path = os.path.join(DEPLOYMENT_DIR, file_name)
            
            with open(new_file_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)

            # Store the mapping for the final report table
            agent_name = os.path.splitext(file_name)[0].replace('_', ' ').replace(' Agent', '')
            uuid_mappings.append((agent_name, new_uuid))

        except Exception as e:
            print(f"⚠️  Could not process file {file_path}: {e}")

    # 5. Zip the content of the deployment folder
    print(f"\n📦 Creating zip archive: '{ZIP_NAME}.zip'...")
    shutil.make_archive(ZIP_NAME, 'zip', DEPLOYMENT_DIR)

    # 6. Notify the user that the process is complete
    print(f"🎉 Deployment package '{ZIP_NAME}.zip' is ready!")

    # --- NEW: Clean up the temporary deployment folder ---
    print(f"🧹 Cleaning up the '{DEPLOYMENT_DIR}' directory...")
    shutil.rmtree(DEPLOYMENT_DIR)

    # 7. Print the summary table of generated UUIDs
    print("\n--- UUID Assignment Summary ---")
    print("| {:<20} | {:<36} |".format("Agent Name", "UUID"))
    print("|-" + "-"*20 + "|-" + "-"*36 + "|")
    for name, uid in sorted(uuid_mappings): # Sorted for consistent output
        print(f"| {name:<20} | {uid:<36} |")
    print("---------------------------------------------------------")


if __name__ == '__main__':
    create_deployment_package()
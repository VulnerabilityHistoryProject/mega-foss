import os
import yaml
from pydriller import Git
import subprocess

def main():
    # Get the absolute path to the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Clone vulnerabilities repo
    subprocess.run(['git', 'clone', 'https://github.com/VulnerabilityHistoryProject/vulnerabilities.git', os.path.join(current_dir, 'vulnerabilities')], check=True)
    try:
        # Retrieve the git commit URL prefix and project name for each project
        project_repo_data = []
        projects_root = os.path.join(current_dir, 'vulnerabilities', 'projects')
        for _, _, projects in os.walk(projects_root):
            for project in projects:
                project_path = os.path.join(projects_root , project)
                with open(project_path, 'r') as f:
                    yaml_data = yaml.safe_load(f)
                    if 'git_commit_url_prefix' in yaml_data and 'name' in yaml_data:
                        project_repo_data.append({
                        'name': yaml_data['name'],
                        'commit_prefix': yaml_data['git_commit_url_prefix']
                        })

        # Retrieve commit hashes for each CVE 
        # Valid CVE files contain a field "fixes.commit" with the hash of the commit that fixed the vulnerability.
        project_data = []
        for project in project_repo_data:
            cves_root = os.path.join(current_dir, 'vulnerabilities', 'cves', project['name'])
            for _, _, cves in os.walk(cves_root):
                for cve in cves:
                    cves_path = os.path.join(cves_root, cve)
                    with open(cves_path, 'r') as f:
                        try:
                            cve_data = yaml.safe_load(f)
                            if 'fixes' in cve_data and cve_data['fixes']:
                                for fix in cve_data['fixes']:
                                    if 'commit' in fix and fix['commit']:
                                        project_data.append({
                                            'commit_url_prefix': project['commit_prefix'],
                                            'cve': cve_data["CVE"],
                                            'commit': fix['commit']
                                        })
                        except Exception as e:
                            # make this error print red
                            print(f"\033[91mError processing CVE file {cves_path}: {e}\033[0m")
                            continue


        # Parse the project data for cve, commit, and commit_url_prefix for each cve
        # Using pydriller, retrieve the files affected by this commit hash, before and after the fix.
        patched_files = os.path.join(current_dir, 'vhp_patched_files')
        subprocess.run(['mkdir', '-p', patched_files], check=True)
        for project in project_data:
            # cloning locally for testing purposes
            project_repo = project['commit_url_prefix'][:-7]
            clone_path = os.path.join(current_dir, 'cloned_repo')
            subprocess.run(['git', 'clone', project_repo, clone_path], check=True)

            try:
                gr = Git(clone_path)
                modified_files = gr.get_commit(project['commit']).modified_files

                # Create a directory for the CVE
                cve_dir = os.path.join(patched_files, project['cve'])
                subprocess.run(['mkdir', '-p', cve_dir], check=True)
                
                old_files_path = os.path.join(cve_dir, f"{project['commit']}-old")
                new_files_path = os.path.join(cve_dir, f"{project['commit']}-new")
                subprocess.run(['mkdir', '-p', old_files_path], check=True)
                subprocess.run(['mkdir', '-p', new_files_path], check=True)

                # Save affected files before and after the commit
                for file in modified_files:
                    with open(os.path.join(cve_dir, f"{project['commit']}.patch"), 'w') as patch_file:
                        patch_file.write(file.diff)
                    with open(os.path.join(old_files_path, file.filename), 'w') as old_file:
                        old_file.write(file.source_code_before)
                    with open(os.path.join(new_files_path, file.filename), 'w') as new_file:
                        new_file.write(file.source_code)
            except Exception as e:
                print(f"\033[91mError processing commit {project['commit']} in repo {project_repo}: {e}\033[0m")
                # Clean up by removing the cloned project repo
                subprocess.run(['rm', '-rf', clone_path], check=True)
                continue
            # Clean up by removing the cloned project repo
            subprocess.run(['rm', '-rf', clone_path], check=True)

    except Exception as e:
        #print error and trace stack
        import traceback
        traceback.print_exc()
        print(f"An error occurred: {e}")
        # Clean up by removing the cloned vulnerabilities repo
        subprocess.run(['rm', '-rf', os.path.join(current_dir, 'vulnerabilities')], check=True)
        return
    
    # Clean up by removing the cloned vulnerabilities repo
    subprocess.run(['rm', '-rf', os.path.join(current_dir, 'vulnerabilities')], check=True)
    return

if __name__ == "__main__":
    main()
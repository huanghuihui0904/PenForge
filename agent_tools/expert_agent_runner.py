# agent_tools/expert_agent_runner.py

import os
import subprocess
from datetime import datetime
import signal
import atexit
from pathlib import Path
from dotenv import load_dotenv
import requests

# Find repository root and load .env file
repo_root = Path(__file__).parent.parent
env_path = repo_root / ".env"
load_dotenv(dotenv_path=env_path)

class ExpertAgentRunner:
    def __init__(self,CVE ,DIFFICULTY,NETWORK_NAME,script_output_root_dir):
        self.base_dir = "./autogpt"
        self.dockerfile_name = "Dockerfile.meta_planner"
        self.cve = CVE
        self.image_name = "autogpt"
        self.container_name = "autogpt-container"
        self.network_name = NETWORK_NAME
        self.model = os.getenv("MODEL")
        self.difficulty = "meta_planner_agent-autogpt-cvebench-"+  DIFFICULTY
        self.main_timestamp =""
        self.step_summaries_path=""
        self.script_output_root_dir = script_output_root_dir
        self.logs_dir = "../output-logs"
   

    def build_image(self):
        import hashlib
        from pathlib import Path

        dockerfile_path = Path(self.base_dir) / self.dockerfile_name
        hash_file = Path(self.base_dir) / ".dockerfile.hash"

        sha256 = hashlib.sha256()
        with open(dockerfile_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        current_hash = sha256.hexdigest()

        if hash_file.exists():
            previous_hash = hash_file.read_text().strip()
            if previous_hash == current_hash:
                result = subprocess.run(
                    ["docker", "images", "-q", self.image_name],
                    capture_output=True, text=True
                )
                if result.stdout.strip():
                    print("[INFO] Dockerfile unchanged and image exists. Skipping build.")
                    return
                else:
                    print("Dockerfile unchanged but image missing. Building...")
            else:
                print("Dockerfile changed. Rebuilding...")
        else:
            print("No previous hash found. Building image...")

        subprocess.run([
            "sudo", "docker", "build", ".",
            "-f", self.dockerfile_name,
            "-t", self.image_name
        ], cwd=self.base_dir, check=True)

        hash_file.write_text(current_hash)
        print("[INFO] Build complete and hash updated.")



    def cleanup_old_container(self):
        print("[INFO] Cleaning up old container if exists...")
        
        result = subprocess.run(
            ["docker", "ps", "-a", "-q", "-f", f"name={self.container_name}"],
            capture_output=True, text=True
        )

        if result.stdout.strip():
            subprocess.run(["sudo", "docker", "rm", "-f", self.container_name], check=False)
            print(f"[INFO] Removed container: {self.container_name}")
        else:
            print(f"[ERROR] No container named '{self.container_name}' found.")
        

    def determine_mount_option(self):

        mount_options = []
        
                
        scan_results_file="./agent_tools/endpointscan_results/endpoint_scan_results.txt"
        try:
            os.makedirs(os.path.dirname(scan_results_file), exist_ok=True)
            if not os.path.exists(scan_results_file):
                with open(scan_results_file, "w", encoding="utf-8") as f:
                    f.write("")
            mount_options.append(
                f"-v {scan_results_file}:/tmp/endpoint_scan_results.txt:ro"
            )
            print(
                f"[INFO] Will mount scan results: {scan_results_file} -> /tmp/endpoint_scan_results.txt"
            )
        except Exception as e:
            print(f"[ERROR] Could not prepare scan results file for mounting: {e}")
            
        webpage_results_file="./agent_tools/webpage_results/webpage_read_results.txt"
        try:
            os.makedirs(os.path.dirname(webpage_results_file), exist_ok=True)
            if not os.path.exists(webpage_results_file):
                with open(webpage_results_file, "w", encoding="utf-8") as f:
                    f.write("") 
            mount_options.append(
                f"-v {webpage_results_file}:/tmp/webpage_read_results.txt:ro"
            )
            print(
                f"[INFO] Will mount scan results: {webpage_results_file} -> /tmp/webpage_read_results.txt"
            )
        except Exception as e:
            print(f"[ERROR] Could not prepare scan results file for mounting: {e}")

        if not mount_options:
            print(f"[ERROR] No relevant files found for {self.cve}. Running without mounting any.")
            return ""
        return " ".join(mount_options)


    def run_container(self):
        print("Running Docker container with expert agent script...")
        log_dir = os.path.join(self.logs_dir, "logs-autogpt")
        os.makedirs(log_dir, exist_ok=True)

        mount_option = self.determine_mount_option().split()

        docker_run_cmd = [
            "sudo", "docker", "run",
            "--name", self.container_name,
            "--network", self.network_name,
            "-v", "/.venv:/app/.venv",
            "-v", "/.cache:/root/.cache",
            "-v", f"{log_dir}:/logs",
            "-v", f"{self.script_output_root_dir}:/app/classic/original_autogpt/expert_agent_script",
            "-e", f"CVE={self.cve}",
            "-e", f"DIFFICULTY={self.difficulty}",
            "-e", f"MODEL={self.model}",
            "-e", f"EXPERT_AGENT_SCRIPT_PATH={self.expert_agent_script_path}",
        ] + mount_option + [
            self.image_name
        ]

        def cleanup(signum=None, frame=None):
            print("[INFO] Signal received. Cleaning up Docker container...")
            try:
                subprocess.run(["sudo", "docker", "rm", "-f", self.container_name], check=True)
            except subprocess.CalledProcessError as e:
                if "No such container" in e.stderr.decode() if e.stderr else str(e):
                    print(f"[ERROR] Container {self.container_name} already removed.")
                else:
                    print(f"[ERROR] Failed to remove container: {e}")


        atexit.register(cleanup)
        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGTERM, cleanup)

        try:
            subprocess.run(docker_run_cmd, cwd=self.base_dir)
        except KeyboardInterrupt:
            cleanup()



    def copy_logs(self):
        log_base = os.path.join(self.logs_dir, f"logs-{self.difficulty}-{self.model}", self.cve,self.main_timestamp)

        filename_no_ext = os.path.splitext(os.path.basename(self.expert_agent_script_path))[0]
        archive_dir = os.path.join(log_base, f"{filename_no_ext}")
        self.step_summaries_path = os.path.join(archive_dir, "step_summaries.txt")
        os.makedirs(archive_dir, exist_ok=True)

        subprocess.run(["sudo", "docker", "cp", f"{self.container_name}:/app/classic/original_autogpt/environment/{self.cve}", archive_dir])
        subprocess.run(["sudo", "docker", "cp", f"{self.container_name}:/logs/thoughts.jsonl", os.path.join(archive_dir, "thoughts.jsonl")])
        subprocess.run(["sudo", "docker", "cp", f"{self.container_name}:/logs/step_summaries.txt", os.path.join(archive_dir, "step_summaries.txt")])

        print(f"[INFO] Agent execution completed. Logs saved to {archive_dir}")

    def return_step_summaries(self) -> str:
        if not os.path.exists(self.step_summaries_path):
            return f"[ERROR] No step summaries found at {self.step_summaries_path}."

        with open(self.step_summaries_path, "r") as f:
            step_summaries = [line.strip() for line in f.readlines() if line.strip()]

        if not step_summaries:
            return "[ERROR] No step summaries found in the file."

        return "\n".join(step_summaries)

    def verify_post_attack_state(self) -> str:
        """
        After each expert agent run, hit the benchmark endpoint
        http://localhost:9091/done. This endpoint returns
        {"message":"Outbound service successful","status":true} when the attack
        actually succeeded, or {"message":"Attack unsuccessful","status":false}
        otherwise. We append this snapshot to the step summaries so
        MetaPlanner can rely on the target's ground-truth verdict.
        """
        url = "http://localhost:9091/done"
        try:
            resp = requests.get(url, timeout=8)
            body = resp.text.strip().replace("\r", "")
            return (
                "[POST-RUN TARGET SNAPSHOT]\n"
                f"{url} -> status {resp.status_code}\n"
                f"Response: {body}"
            )
        except Exception as exc:
            return (
                "[POST-RUN TARGET SNAPSHOT]\n"
                f"{url} -> ERROR: {exc}"
            )


    def run(self,expert_agent_script_path,main_timestamp)-> str:
        self.expert_agent_script_path = expert_agent_script_path
        self.main_timestamp = main_timestamp
        self.build_image()
        self.cleanup_old_container()
        self.run_container()
        self.copy_logs()
        step_summary = self.return_step_summaries()
        verification = self.verify_post_attack_state()
        return f"{step_summary}\n\n{verification}"


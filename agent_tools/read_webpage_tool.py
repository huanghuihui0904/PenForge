import os
import time
import subprocess
from urllib.parse import urlparse, urlunparse
from typing import Optional


class WebpageReader:
    def __init__(
        self,
        NETWORK_NAME: str,
        host_output_dir: str = "./agent_tools/webpage_results",
        image_name: str = "webtool-image",
        container_name: str = "webtool-container",
        dockerfile_name: str = "Dockerfile.simple",
    ) -> None:
        self.image_name = image_name
        self.runner_container = container_name
        self.network = NETWORK_NAME
        self.dockerfile_name = dockerfile_name

        self.host_output_dir = host_output_dir
        self.output_file = os.path.join(self.host_output_dir, "webpage_read_results.txt")
        os.makedirs(self.host_output_dir, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write("")

    def _run_cmd(self, cmd: list, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

    def _container_running(self) -> bool:
        proc = self._run_cmd(["sudo", "docker", "ps", "--filter", f"name=^{self.runner_container}$", "--format", "{{.Names}}"])
        return self.runner_container in proc.stdout.strip().splitlines()

    def _ensure_container(self) -> None:
        if self._container_running():
            print(f"[INFO] Reusing running container '{self.runner_container}'.")
            return

        print(f"Removing any stale container '{self.runner_container}'...")
        subprocess.run(["sudo", "docker", "rm", "-f", self.runner_container],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print("Building image...")
        build = self._run_cmd(
            ["sudo", "docker", "build", "-f", self.dockerfile_name, "-t", self.image_name, "."],
            timeout=600
        )
        if build.returncode != 0:
            raise RuntimeError(f"Docker build failed:\n{build.stdout}\n{build.stderr}")

        print("Starting container...")
        run = self._run_cmd(
            ["sudo", "docker", "run", "-d", "--rm", "--name", self.runner_container, "--network", self.network, self.image_name],
            timeout=60
        )
        if run.returncode != 0:
            raise RuntimeError(f"Docker run failed:\n{run.stdout}\n{run.stderr}")

        time.sleep(2)
        print("[INFO] Container running.")

    def _cleanup_container(self) -> None:
        try:
            disc = subprocess.run(
                ["sudo", "docker", "network", "disconnect", "-f", self.network, self.runner_container],
                capture_output=True, text=True, timeout=30, check=False
            )
            if disc.returncode == 0:
                print(f"[INFO] Disconnected container '{self.runner_container}' from network '{self.network}'.")
            else:
                stderr = (disc.stderr or "").strip()
                if stderr:
                    print(f"[debug] network disconnect returned non-zero: {stderr}")
        except Exception as e:
            print(f"[debug] Exception while disconnecting network: {e}")

        try:
            rm = subprocess.run(
                ["sudo", "docker", "rm", "-f", self.runner_container],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False
            )
            if rm.returncode == 0:
                print(f"[INFO] Removed container '{self.runner_container}'.")
            else:
                stderr = (rm.stderr or "").strip()
                if stderr:
                    print(f"[ERROR] docker rm returned non-zero: {stderr}")
        except Exception as e:
            print(f"[ERROR] Exception while removing container: {e}")

    def _normalize_url(self, url: str, default_scheme: str = "http") -> str:
        if "://" not in url:
            url = f"{default_scheme}://{url}"
        p = urlparse(url)
        scheme = p.scheme or default_scheme
        host = p.hostname or "localhost"
        port = p.port
        if not port:
            port = 443 if scheme == "https" else 80
        return urlunparse((scheme, f"{host}:{port}", p.path or "/", "", "", ""))

    def _save_output(self, url: str, text: str) -> None:
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(f"\n=== FETCH {url} ===\n")
            f.write(text.strip() + "\n")

    def run(self, target_url: str, insecure: bool = False, return_max_chars: Optional[int] = 5000) -> str:
        try:
            clean_url = self._normalize_url(target_url)
            print(f"[WebpageReader] Fetching {clean_url} ...")
            self._ensure_container()

            cmd = ["sudo", "docker", "exec", self.runner_container, "curl", "-sL"]
            if insecure:
                cmd.append("-k") 
            cmd.append(clean_url)

            result = self._run_cmd(cmd, timeout=30)
            output = (result.stdout or "").strip()

            if result.returncode != 0:
                output += f"\n[ERROR] curl exit code {result.returncode}\n{result.stderr}"

            self._save_output(clean_url, output or "[empty page]")

            return_text = output
            if (
                return_text
                and isinstance(return_max_chars, int)
                and return_max_chars > 0
                and len(return_text) > return_max_chars
            ):
                return_text = (
                    return_text[:return_max_chars]
                    + f"\n[truncated to {return_max_chars} chars]"
                )

            print(f"[WebpageReader] Fetch complete.")
            return return_text
        except Exception as e:
            err = f"[WebpageReader] Error: {e}"
            print(err)
            return err
        finally:
            try:
                self._cleanup_container()
            except Exception as e:
                print(f"[ERROR] Cleanup raised unexpected exception: {e}")

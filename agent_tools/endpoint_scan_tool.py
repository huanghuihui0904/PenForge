import os
import re
import time
import subprocess
from urllib.parse import urlparse, urlunparse
from typing import Iterable, List, Optional


class EndpointScanner:
    def __init__(
        self,
        NETWORK_NAME: str ,
        host_output_dir: str = "./agent_tools/endpointscan_results",
        image_name: str = "webtool-image",
        container_name: str = "webtool-container",
        dockerfile_dir: str = "./",
        dockerfile_name: str = "Dockerfile.simple",
        wordlist_common_path: str = "/app/common.txt",
        wordlist_api_endpoint: str = "/app/api-endpoints.txt",
        default_excludes: Optional[Iterable[str]] = None,
    ) -> None:
        self.image_name = image_name
        self.runner_container = container_name
        self.network = NETWORK_NAME
        self.dockerfile_dir = dockerfile_dir
        self.dockerfile_name = dockerfile_name

        self.wordlist_common_path = wordlist_common_path
        self.wordlist_api_endpoint = wordlist_api_endpoint

        self.host_output_dir = host_output_dir
        self.output_file = os.path.join(self.host_output_dir, "endpoint_scan_results.txt")
        os.makedirs(self.host_output_dir, exist_ok=True)

        self.default_excludes = list(default_excludes) if default_excludes is not None else [
            r"\.git(?:/|$)",
            r"\.svn(?:/|$)",
            r"\.hg(?:/|$)",
            r"\.DS_Store(?:/|$)",
        ]

        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write("")

    def _truncate_output(self, text: str, max_lines: int = 100) -> str:
        raw_lines = text.splitlines()

        lines = [ln for ln in raw_lines if ln.strip()]

        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n...[truncated {len(lines)-max_lines} lines]..."
        return "\n".join(lines)

    
    @staticmethod
    def _safe_scheme_port(scheme: str, port: Optional[int]) -> (str, int):
        if port is None:
            port = 443 if scheme == "https" else 80
        if port == 80 and scheme == "https":
            scheme = "http"
        if port == 443 and scheme == "http":
            scheme = "https"
        return scheme, port

    @staticmethod
    def _ensure_trailing_slash(path: str) -> str:
        return path if path.endswith("/") else (path + "/")

    def _normalize_url(self, url: str, default_scheme: str = "http") -> str:
        cleaned = url.strip().replace("url = ", "").replace("=", "").replace("url", "").strip()
        if "://" not in cleaned:
            cleaned = f"{default_scheme}://{cleaned}"

        p = urlparse(cleaned)
        scheme, port = self._safe_scheme_port(p.scheme or default_scheme, p.port)
        host = p.hostname or "localhost"
        path = self._ensure_trailing_slash(p.path or "/")

        return urlunparse((scheme, f"{host}:{port}", path, "", "", ""))

    def _combine_excludes_regex(self, extra_excludes: Optional[Iterable[str]]) -> Optional[str]:
        patterns = list(self.default_excludes)
        if extra_excludes:
            patterns.extend(list(extra_excludes))

        if not patterns:
            return None

        grouped = [f"(?:{p})" for p in patterns]
        return "|".join(grouped)

    def _append_output(self, label: str, text: str) -> None:
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(f"\n=== {label.upper()} SCAN ===\n")
            f.write(text.rstrip() + "\n")

    def _run_cmd(self, cmd: List[str], timeout: int = 600) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


    def _container_running(self) -> bool:
        proc = self._run_cmd(["sudo", "docker", "ps", "--filter", f"name=^{self.runner_container}$", "--format", "{{.Names}}"])
        return self.runner_container in proc.stdout.strip().splitlines()

    def _ensure_container(self) -> None:
        if self._container_running():
            print(f"[INFO] Reusing running container '{self.runner_container}'.")
            return

        print(f"[INFO] Removing any stale container named '{self.runner_container}'...")
        subprocess.run(["sudo", "docker", "rm", "-f", self.runner_container],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print("[INFO] Building image...")
        build = self._run_cmd(
            ["sudo", "docker", "build", "-f", self.dockerfile_name, "-t", self.image_name, "."],
            timeout=1800
        )
        if build.returncode != 0:
            raise RuntimeError(f"Docker build failed:\nSTDOUT:\n{build.stdout}\nSTDERR:\n{build.stderr}")

        print("[INFO] Starting container...")
        run = self._run_cmd(
            ["sudo", "docker", "run", "-d", "--rm", "--name", self.runner_container, "--network", self.network, self.image_name],
            timeout=120
        )
        if run.returncode != 0:
            raise RuntimeError(f"Docker run failed:\nSTDOUT:\n{run.stdout}\nSTDERR:\n{run.stderr}")

        time.sleep(3)
        print("[INFO] Webtool container is running.")

    def _cleanup_container(self) -> None:
        try:
            disc = subprocess.run(["sudo", "docker", "network", "disconnect", "-f", self.network, self.runner_container],
                                  capture_output=True, text=True, timeout=30, check=False)
            if disc.returncode == 0:
                print(f"[INFO] Disconnected container '{self.runner_container}' from network '{self.network}'.")
            else:
                stderr = disc.stderr.strip()
                if stderr:
                    print(f"[ERROR] network disconnect returned non-zero: {stderr}")
        except Exception as e:
            print(f"[ERROR] Exception while disconnecting network: {e}")

        try:
            rm = subprocess.run(["sudo", "docker", "rm", "-f", self.runner_container],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
            if rm.returncode == 0:
                print(f"[INFO] Removed container '{self.runner_container}'.")
            else:
                stderr = rm.stderr.strip()
                if stderr:
                    print(f"[ERROR] docker rm returned non-zero: {stderr}")
        except Exception as e:
            print(f"[ERROR] Exception while removing container: {e}")


    def _run_scan(
        self,
        label: str,
        base_url: str,
        wordlist: str,
        threads: int = 30,
        timeout: int = 10,
        depth: Optional[int] = None,
        extensions: Optional[Iterable[str]] = None,
        allow_redirects: bool = True,
        status_codes: str = "200,301,302,403,405,500",
        insecure: bool = False,
        exclude_regex: Optional[str] = None,
    ) -> str:
        cmd = [
            "sudo", "docker", "exec", self.runner_container,
            "feroxbuster",
            "--url", base_url,
            "--wordlist", wordlist,
            "--threads", str(threads),
            "--timeout", str(timeout),
            "--status-codes", status_codes,
        ]

        if depth is not None:
            cmd.extend(["--depth", str(depth)])
        if extensions:
            cmd.extend(["--extensions", ",".join(extensions)])
        if allow_redirects:
            cmd.append("--redirects")
        if insecure and base_url.startswith("https://"):
            cmd.append("-k")
        if exclude_regex:
            cmd.extend(["--filter-regex", exclude_regex])

        print(f"[EndpointScanner] Running {label} scan...")
        try:
            result = self._run_cmd(cmd, timeout=max(600, timeout * 20))  # generous cap for big wordlists
        except subprocess.TimeoutExpired:
            msg = "[ERROR] feroxbuster scan reached timeout — partial results may still be valid."
            self._append_output(label, msg)
            return msg
        except Exception as e:
            msg = f"[ERROR] Unexpected error: {e}"
            self._append_output(label, msg)
            return msg

        output = (result.stdout or "").strip()
        
        if result.returncode != 0:
            output += f"\n[ERROR] feroxbuster exit code {result.returncode}\nSTDERR:\n{result.stderr}"
        
        output = self._truncate_output(output)

        self._append_output(label, output or "[empty output]")
        print(f"[EndpointScanner] {label} scan complete.")
        return output


    def run(
        self,
        target_url: str,
        insecure: bool = False,
        extra_excludes: Optional[Iterable[str]] = None,
    ) -> str:
        try:
            clean_url = self._normalize_url(target_url)
            print(f"[EndpointScanner] Scanning {clean_url} via {self.runner_container}...")
            self._ensure_container()

            exclude_regex = self._combine_excludes_regex(extra_excludes)

            flat_output = self._run_scan(
                label="flat ssrf endpoint",
                base_url=clean_url,
                wordlist=self.wordlist_api_endpoint,
                threads=30,
                timeout=10,
                depth=None,                     # no recursion
                extensions=None,
                allow_redirects=True,
                status_codes="200,301,302,403,405,500",
                insecure=insecure,
                exclude_regex=exclude_regex,
            )

            deep_output = self._run_scan(
                label="deep recursive",
                base_url=clean_url,
                wordlist=self.wordlist_common_path,
                threads=30,
                timeout=10,
                depth=3,
                extensions=["php", "html", "txt"],
                allow_redirects=True,
                status_codes="200,301,302,403,405,500",
                insecure=insecure,
                exclude_regex=exclude_regex,
            )

            return f"{flat_output}\n\n{deep_output}"

        except Exception as e:
            err = f"[EndpointScanner] Error during run: {e}"
            print(err)
            return "[EndpointScanner] fail, please retry with proper url again"

        finally:
            try:
                self._cleanup_container()
            except Exception as e:
                print(f"[ERROR] Cleanup raised unexpected exception: {e}")


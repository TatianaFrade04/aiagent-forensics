# Forensic Docker Environment — Setup Log

This documents the steps to build a Docker-based forensic environment where a Python + LLM agent can run investigation commands against a forensic disk image.

---

## 1.1 — Verify Docker is Working

Docker lets you run a lightweight, isolated Linux environment on any machine. Think of it as a mini virtual machine that boots instantly.

```powershell
docker run hello-world
```

This downloads a small test image and runs it. If you see `Hello from Docker!` → Docker is installed and running correctly.

---

## 1.2 — Create the Dockerfile

The Dockerfile is a recipe that tells Docker what to put inside your container — which OS, which tools, which folder to work in.

```powershell
New-Item Dockerfile
```

Paste this content into the file:

```dockerfile
FROM ubuntu:22.04

RUN apt update && apt install -y \
    sleuthkit \
    grep \
    findutils \
    coreutils \
    python3

WORKDIR /app
```

What each line does:

| Line | Meaning |
|------|---------|
| `FROM ubuntu:22.04` | Start from a clean Ubuntu 22.04 Linux |
| `RUN apt install ...` | Install the tools listed below |
| `WORKDIR /app` | All commands will run inside `/app` by default |

Tools installed:

| Tool | Purpose |
|------|---------|
| `sleuthkit` | Forensic tools: `fls` (list files), `mmls` (list partitions) |
| `grep` | Search for text patterns inside files |
| `findutils` | `find` command — search for files by name/type |
| `coreutils` | Basic Linux commands (`ls`, `echo`, etc.) |
| `python3` | Run the Python agent scripts |

---

## 1.3 — Build the Docker Image

Now we turn the Dockerfile into an actual image (a snapshot ready to run).

```powershell
docker build -t forensic-agent .
```

- `-t forensic-agent` names the image `forensic-agent`
- `.` means "use the Dockerfile in the current folder"

Launch the container and open a terminal inside it:

```powershell
docker run -it forensic-agent bash
```

Inside the container, confirm the tools are available:

```bash
grep --version   # should print version info
find --version   # should print version info
fls              # should print usage help (part of sleuthkit)
```

If all three respond → image was built correctly.

---

## 1.4 — Mount the Forensic Image into the Container

The forensic evidence file lives on your Windows machine. We mount it into the container as a read-only folder so the tools inside can access it without being able to modify it.

```powershell
mkdir evidence
# Copy 2020JimmyWilson.E01 into the evidence/ folder

docker run -it -v ${PWD}\evidence:/evidence:ro forensic-agent bash
```

- `-v ${PWD}\evidence:/evidence` mounts your local `evidence/` folder to `/evidence` inside the container
- `:ro` = read-only (safe — nothing can overwrite the evidence)

Inside the container, verify the file is visible:

```bash
ls /evidence
# → 2020JimmyWilson.E01
```

Inspect the partition layout of the disk image:

```bash
mmls -i ewf /evidence/2020JimmyWilson.E01
# Prints a partition table with offsets (e.g. 65664)
```

Use the offset to list the files inside the partition:

```bash
fls -i ewf -o 65664 /evidence/2020JimmyWilson.E01
# Lists every file and directory in the filesystem
```

`-i ewf` tells the tool the image is in EnCase (E01) format. The offset tells it where the partition starts on the disk.

---

## 1.5 — Test Forensic Commands

Final sanity check — confirm the container can actually run investigation commands and return useful output.

```bash
find /evidence          # recursively list all files in the evidence folder
```

Test `grep` with a small file:

```bash
echo "password=1234" > /app/test.txt
grep "password" -r /app
# → /app/test.txt:password=1234
```

`grep -r` searches recursively through all files in a folder for a text pattern. This is exactly the kind of command the agent will use during an investigation.

If all commands return output → environment is fully ready.


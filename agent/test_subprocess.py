from tools.runner import run_cmd

print(run_cmd(["ls", "-la", "/evidence"]))
print(run_cmd(["mmls", "-i", "ewf", "/evidence/2020JimmyWilson.E01"]))
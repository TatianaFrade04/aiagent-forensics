from tools.commands import list_dir, find_on_mounted, mmls_partitions, fls_list

E01 = "/evidence/2020JimmyWilson.E01"
OFFSET = "65664"  # troca para o teu offset real (do mmls)

print("== list_dir /evidence ==")
print(list_dir("/evidence"))

print("== find_on_mounted /evidence ==")
print(find_on_mounted("/evidence"))

print("== mmls ==")
print(mmls_partitions(E01))

print("== fls raiz (offset) ==")
print(fls_list(E01, OFFSET))
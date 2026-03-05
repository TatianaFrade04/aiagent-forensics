from tools.commands import (
    list_dir,
    find_on_mounted,
    mmls_partitions,
    fls_list,
    grep_recursive
)

E01_DEFAULT = "/evidence/2020JimmyWilson.E01"
OFFSET_DEFAULT = "65664"  # troca para o teu offset real

def main():
    print("Agente Forense (simples)")
    print("Comandos: listar_evidence | find_evidence | particoes | listar_imagem | grep_app | sair")
    print()

    while True:
        cmd = input("> ").strip().lower()

        if cmd in ("sair", "exit", "quit"):
            break

        elif cmd == "listar_evidence":
            print(list_dir("/evidence"))

        elif cmd == "find_evidence":
            print(find_on_mounted("/evidence"))

        elif cmd == "particoes":
            e01 = input(f"Caminho E01 [{E01_DEFAULT}]: ").strip() or E01_DEFAULT
            print(mmls_partitions(e01))

        elif cmd == "listar_imagem":
            e01 = input(f"Caminho E01 [{E01_DEFAULT}]: ").strip() or E01_DEFAULT
            offset = input(f"Offset [{OFFSET_DEFAULT}]: ").strip() or OFFSET_DEFAULT
            print(fls_list(e01, offset))

        elif cmd == "grep_app":
            pattern = input("Padrão (ex: password): ").strip()
            path = input("Path para grep [/app]: ").strip() or "/app"
            print(grep_recursive(pattern, path))

        else:
            print("Não reconhecido. Usa: listar_evidence | find_evidence | particoes | listar_imagem | grep_app | sair")

if __name__ == "__main__":
    main()
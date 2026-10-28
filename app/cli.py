from __future__ import annotations

import argparse
import getpass
import sys

from app.config import get_settings
from app.security.passwords import hash_password
from app.storage.factory import get_config_storage
from app.storage.repository import utcnow

__all__ = ["main"]


def _read_password(confirm: bool = True) -> str:
    password = getpass.getpass("Пароль: ")
    if confirm:
        again = getpass.getpass("Повторите пароль: ")
        if password != again:
            raise SystemExit("Пароли не совпадают")
    if len(password) < 8:
        raise SystemExit("Пароль должен содержать не менее 8 символов")
    return password


def create_admin(args: argparse.Namespace) -> int:
    repository = get_config_storage()
    login = args.login or get_settings().admin_login
    if repository.fetch_one("users", "login=?", (login,)) is not None:
        print(f"Пользователь {login} уже существует", file=sys.stderr)
        return 1
    password = _read_password()
    repository.insert_row(
        "users",
        {
            "login": login,
            "password_hash": hash_password(password),
            "is_admin": 1,
            "created_at": utcnow().isoformat(),
        },
    )
    repository.append_audit("user.create", details="создан администратор через CLI")
    print(f"Администратор {login} создан")
    return 0


def set_password(args: argparse.Namespace) -> int:
    repository = get_config_storage()
    user = repository.fetch_one("users", "login=?", (args.login,))
    if user is None:
        print(f"Пользователь {args.login} не найден", file=sys.stderr)
        return 1
    password = _read_password()
    repository.update("users", user["id"], password_hash=hash_password(password))
    repository.append_audit(
        "user.password",
        user_id=user["id"],
        details="смена пароля через CLI",
    )
    print("Пароль обновлён")
    return 0


def list_users(_: argparse.Namespace) -> int:
    repository = get_config_storage()
    users = repository.fetch_all("users", "ORDER BY id")
    if not users:
        print("Пользователей нет")
        return 0
    for user in users:
        role = "admin" if user["is_admin"] else "user"
        print(f"{user['id']}\t{user['login']}\t{role}\t{user['created_at'] or ''}")
    return 0


def init_db(_: argparse.Namespace) -> int:
    repository = get_config_storage()
    print(f"Схема готова: {repository.db_path}")
    return 0


def serve(_: argparse.Namespace) -> int:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.debug,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netshield", description="NetShield CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-admin", help="создать администратора")
    p.add_argument("--login", default=None)
    p.set_defaults(func=create_admin)

    p = sub.add_parser("set-password", help="сменить пароль пользователя")
    p.add_argument("login")
    p.set_defaults(func=set_password)

    p = sub.add_parser("list-users", help="список пользователей")
    p.set_defaults(func=list_users)

    p = sub.add_parser("init-db", help="создать/обновить схему БД")
    p.set_defaults(func=init_db)

    p = sub.add_parser("serve", help="запустить API")
    p.set_defaults(func=serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

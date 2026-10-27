"""Create a NEW restricted-demo account interactively; never reset an existing user."""
import argparse
import getpass
from passlib.context import CryptContext
from demo_runtime import restricted_demo


def main():
    if not restricted_demo():
        raise SystemExit("Account provisioning requires restricted-demo mode and its fresh DATABASE_URL")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    if len(args.email) > 254 or "@" not in args.email:
        raise SystemExit("Use a valid demonstration account identifier")
    password = getpass.getpass("New demo account password (12+ characters, not a real personal password): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm or len(password) < 12 or len(password.encode()) > 72:
        raise SystemExit("Passwords must match and contain 12+ characters, at most 72 UTF-8 bytes")
    from database import SessionLocal, User
    with SessionLocal() as db:
        if db.query(User).filter(User.email == args.email).first():
            raise SystemExit("That account already exists; no record was changed")
        db.add(User(email=args.email, hashed_password=CryptContext(schemes=["bcrypt"]).hash(password)))
        db.commit()
    print("New demonstration account created. No existing user was changed.")


if __name__ == "__main__":
    main()

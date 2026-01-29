# To test:
#
#  # build extension locally and install it in the venv
#  python -m venv .venv
#  source .venv/bin/activate
#  cd python
#  RUSTFLAGS="-C link-arg=-Wl,-undefined,dynamic_lookup" maturin develop
#  python db-test.py

import rust_native_keyring as rnk

# Create encrypted database 'my-enc.db'
rnk.use_named_store(
    "sqlite",
    {
        "path": "my-enc.db",
        "cipher": "aegis256",
        "hexkey": "3ed45fe875d91c6050a3cf7c3521b8022f934b66710e4eb525001aaaf0d20b90",
    },
)
# print(f"store info: {rnk.store_info()}")

# NOTE: Python strings are immutable and cannot be zeroized. Avoid using real secrets here.
# set password for first user
entry = rnk.Entry("example-app", "alice")
entry.set_password("secret!")

# lookup password and verify
entries = rnk.Entry.search({"service": "example-app", "user": "alice"})
if entries[0].get_password() == "secret!":
    print("Password match")
else:
    print("Access denied!")

# set password for second user
e2 = rnk.Entry("example-app", "bob")
e2.set_password("horse-battery-staple")

# use search to list all users
entries = rnk.Entry.search({"service": "example-app"})
print(list(map(lambda e: e.get_specifiers(), entries)))
rnk.release_store()

# pw-retention
Tool to help keep passwords in memory

Passwords are hashed with SHA512 and a salt and kept in an sqlite database, and running the program will prompt you to enter the passwords in a random order. If you enter in seldom used passwords or passphrases (such as for a rarely used SSH key, or backup verification codes) it will help keep them in memory, and not forget them from never using them, while at the same time never having the passwords stored anywhere, not even in encrypted form. Just run this once a day and run through the passwords you've put in and it will help your password retention.

Licensed under GPLv3

                           Matthew Di Ferrante

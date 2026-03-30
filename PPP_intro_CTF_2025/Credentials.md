---
title: Credentials — PPP Intro CTF 2025
date: 2026-03-28
tags:
  - web
  - sql
event: PPP Intro CTF 2025
difficulty: easy
description: Postgres based sql login credential database injection
---

You will need `ProvideCredentialsSystem.ts` and `initdb.sh` to get more information about this problem.

Let's first take a careful look at the `ProvideCredentialsSystem.ts` file. We can see that the login system uses PostgreSQL as its DB.

```ts
// These lines replace ' with ''.
username = username.replace(/'/g, "''").replace(/union|select/ig, "");
password = password.replace(/'/g, "''").replace(/union|select/ig, "");
// These lines truncate the user's input if the length > 48.
// This will be the important part of this challenge.
username = username.substring(0, 48);
password = password.substring(0, 48);

pool.query<{ id: number; username: string }>(
	`SELECT id, username FROM users WHERE username = '${username}' AND password = '${password}'`
).then((result) => {
	if (this.complete) { throw new Error("Invalid state"); }
	if (result.rowCount !== 1) { throw new Error("Invalid credentials"); }
	if (result.rows[0].id !== this.credentials.id) { throw new Error("Invalid credentials"); }
	this.complete = true;
	this.updatePlayers();
	player.pushUpdate(
		new GameUpdate.ProvideCredentialsResponse({
			success: true,
			message: `Successfully logged in as ${result.rows[0].username}`
		})
	);
})
```

From the code above, we can see the input system filters users' input in 2 separate steps to prevent SQL injection:

1. Replace `'` with `''`
2. Truncate user input to a maximum of 48 characters.

Also, the code requires an exact match on the user ID and password assigned by the game.

#### Step 1: Escaping the Single Quote Filter

To escape the single quotes, we can't use `\'` since this is PostgreSQL. Instead, we can exploit the truncation step.

The truncation happens *after* the first filter runs. So if we enter 47 arbitrary characters (excluding `'`) followed by one `'`, the first filter expands the input to 49 characters (replacing `'` with `''`), and then the truncation cuts off the trailing `'`. The result looks like:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
```

This produces the following SQL query:

```sql
SELECT id, username FROM users WHERE username = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'' AND password = '${password}'
```

The `AND password =` clause becomes part of the string literal — effectively neutralized.

#### Step 2: Bypassing the `UNION`/`SELECT` Filter

The filter `.replace(/union|select/ig, "")` removes any occurrence of `union` or `select` (case-insensitive) from the input, but it only iterates once. This means we can nest the keywords so the removal reconstructs them:

- `uniunionon` → `union`
- `sselectelect` → `select`

Since the `AND password =` clause is already neutralized, anything we put in the password field is directly injected into the SQL query. Using the bypass above, we can inject:

```sql
UNUNIONION SSELECTELECT 1, flag FROM flag--
```

> **Note:** The `1` must be replaced with the specific user ID assigned by the game — see `initdb.sh` for details. The trailing `--` comments out the closing single quote.

This retrieves the flag from the `flag` table.

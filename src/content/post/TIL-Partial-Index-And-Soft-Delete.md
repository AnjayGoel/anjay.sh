---
title: "TIL: Partial Indexes And Soft Delete"
publishDate: 2024-02-21 00:00:00 +0530
tags: [ til,sql,programming ]
description: "Exploring partial indexes in SQL."
slug: TIL-Partial-Index-And-Soft-Delete
---

A partial index is a powerful feature that allows you to create an index only on a subset of rows of the given table based on some conditions. Thus reducing the size of the index and optimizing queries. Its syntax is as follows (in PostgreSQL):

```sql
CREATE INDEX idx_name
ON table_name(cols)
WHERE condition;
```

It is often helpful when you want to avoid indexing on some values that are very frequent in the db but not queried upon. For example, to prevent indexing graduated students in a student table.

```sql
CREATE INDEX student_idx ON students (col_1,col_2,col_3,..)
WHERE enrollment_status != 'GRADUATED'
```

or to exclude unavailable products from an index in a product table

```sql
CREATE INDEX product_idx ON products (col_1,col_2,col_3,..)
WHERE state !='UNAVAILABLE'
```
<br>
Recently, I found them very useful when implementing soft delete. Say you are working to build a social media platform, and your user table looks like this:

```sql
CREATE TABLE users (
    id CHAR(100) PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    profile_picture VARCHAR(100)
);
```

You also have a unique index on the username to enforce unique usernames.

```sql
ALTER TABLE users
ADD CONSTRAINT unique_username_constraint UNIQUE (username);
```

Now you decide to soft-delete users (mark a user as deleted instead of actually deleting them from the DB), so you naively add a new field `state`. Whenever a user is deleted, their `state` is set to `DELETED`.

```sql
ALTER TABLE users
ADD COLUMN state VARCHAR(20) DEFAULT 'ACTIVE';
```

But later, you realize a big flaw with this approach. Because of the unique index, you won't be able to reclaim usernames from deleted users! To fix it, you may be tempted to create a unique index on `username` and `state`. But even this unique index will break when you try to delete a user when another user with the same username was deleted earlier.

So, what to do now? The answer is simple. Just drop the unique constraint and add a partial unique index as follows:

```sql
ALTER TABLE users
DROP CONSTRAINT unique_username;

CREATE UNIQUE INDEX unique_username_idx
ON users (username)
WHERE state != 'DELETED';
```

And voilà, the problem is solved.

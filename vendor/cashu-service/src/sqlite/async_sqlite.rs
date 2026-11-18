//! Simple SQLite
use cdk_common::database::Error;
use cdk_sql_common::database::{DatabaseConnector, DatabaseExecutor, DatabaseTransaction};
use cdk_sql_common::run_db_operation_sync;
use cdk_sql_common::stmt::{query, Column, SqlPart, Statement};
use rusqlite::{ffi, CachedStatement, Connection, Error as SqliteError, ErrorCode};
use tokio::sync::Mutex;

use super::common::{from_sqlite, to_sqlite};

/// Async Sqlite wrapper
#[derive(Debug)]
pub struct AsyncSqlite {
    inner: Mutex<Connection>,
}

impl AsyncSqlite {
    pub fn new(inner: Connection) -> Self {
        Self {
            inner: inner.into(),
        }
    }
}
impl AsyncSqlite {
    fn get_stmt<'a>(
        &self,
        conn: &'a Connection,
        statement: Statement,
    ) -> Result<(String, CachedStatement<'a>), Error> {
        let (sql, placeholder_values) = statement.to_sql()?;

        let new_sql = sql.trim().trim_end_matches("FOR UPDATE");

        let mut stmt = conn
            .prepare_cached(new_sql)
            .map_err(|e| Error::Database(Box::new(e)))?;

        for (i, value) in placeholder_values.into_iter().enumerate() {
            stmt.raw_bind_parameter(i + 1, to_sqlite(value))
                .map_err(|e| Error::Database(Box::new(e)))?;
        }

        Ok((sql, stmt))
    }
}

#[inline(always)]
fn to_sqlite_error(err: SqliteError) -> Error {
    tracing::error!("Failed query with error {:?}", err);
    if let rusqlite::Error::SqliteFailure(
        ffi::Error {
            code,
            extended_code,
        },
        _,
    ) = err
    {
        if code == ErrorCode::ConstraintViolation
            && (extended_code == ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                || extended_code == ffi::SQLITE_CONSTRAINT_UNIQUE)
        {
            Error::Duplicate
        } else {
            Error::Database(Box::new(err))
        }
    } else {
        Error::Database(Box::new(err))
    }
}

/// SQLite trasanction handler
#[allow(missing_debug_implementations)]
pub struct SQLiteTransactionHandler;

#[async_trait::async_trait]
impl DatabaseTransaction<AsyncSqlite> for SQLiteTransactionHandler {
    /// Consumes the current transaction committing the changes
    async fn commit(conn: &mut AsyncSqlite) -> Result<(), Error> {
        query("COMMIT")?.execute(conn).await?;
        Ok(())
    }

    /// Begin a transaction
    async fn begin(conn: &mut AsyncSqlite) -> Result<(), Error> {
        query("BEGIN IMMEDIATE")?.execute(conn).await?;
        Ok(())
    }

    /// Consumes the transaction rolling back all changes
    async fn rollback(conn: &mut AsyncSqlite) -> Result<(), Error> {
        query("ROLLBACK")?.execute(conn).await?;
        Ok(())
    }
}

impl DatabaseConnector for AsyncSqlite {
    type Transaction = SQLiteTransactionHandler;
}

#[async_trait::async_trait]
impl DatabaseExecutor for AsyncSqlite {
    fn name() -> &'static str {
        "sqlite"
    }

    async fn execute(&self, statement: Statement) -> Result<usize, Error> {
        let conn = self.inner.lock().await;

        let (sql, mut stmt) = self
            .get_stmt(&conn, statement)
            .map_err(|e| Error::Database(Box::new(e)))?;

        run_db_operation_sync(&sql, || stmt.raw_execute(), to_sqlite_error)
    }

    async fn fetch_one(&self, statement: Statement) -> Result<Option<Vec<Column>>, Error> {
        let conn = self.inner.lock().await;
        let (sql, mut stmt) = self
            .get_stmt(&conn, statement)
            .map_err(|e| Error::Database(Box::new(e)))?;

        run_db_operation_sync(
            &sql,
            || {
                let columns = stmt.column_count();

                let mut rows = stmt.raw_query();
                rows.next()?
                    .map(|row| {
                        (0..columns)
                            .map(|i| row.get(i).map(from_sqlite))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()
            },
            to_sqlite_error,
        )
    }

    async fn fetch_all(&self, statement: Statement) -> Result<Vec<Vec<Column>>, Error> {
        let conn = self.inner.lock().await;
        let (sql, mut stmt) = self
            .get_stmt(&conn, statement)
            .map_err(|e| Error::Database(Box::new(e)))?;

        let columns = stmt.column_count();

        run_db_operation_sync(
            &sql,
            || {
                let mut rows = stmt.raw_query();
                let mut results = vec![];

                while let Some(row) = rows.next()? {
                    results.push(
                        (0..columns)
                            .map(|i| row.get(i).map(from_sqlite))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                }

                Ok(results)
            },
            to_sqlite_error,
        )
    }

    async fn pluck(&self, statement: Statement) -> Result<Option<Column>, Error> {
        let conn = self.inner.lock().await;
        let (sql, mut stmt) = self
            .get_stmt(&conn, statement)
            .map_err(|e| Error::Database(Box::new(e)))?;

        run_db_operation_sync(
            &sql,
            || {
                let mut rows = stmt.raw_query();
                rows.next()?
                    .map(|row| row.get(0usize).map(from_sqlite))
                    .transpose()
            },
            to_sqlite_error,
        )
    }

    async fn batch(&self, mut statement: Statement) -> Result<(), Error> {
        let sql = {
            let part = statement
                .parts
                .pop()
                .ok_or(Error::Internal("Empty SQL".to_owned()))?;

            if !statement.parts.is_empty() || matches!(part, SqlPart::Placeholder(_, _)) {
                return Err(Error::Internal(
                    "Invalid usage, batch does not support placeholders".to_owned(),
                ));
            }

            if let SqlPart::Raw(sql) = part {
                sql
            } else {
                unreachable!()
            }
        };
        let conn = self.inner.lock().await;

        run_db_operation_sync(&sql, || conn.execute_batch(&sql), to_sqlite_error)
    }
}

import os
import pymssql
from pymssql import _mssql

pswd = ""
pswd2 = get_from_config()

# ruleid: python-pymssql-empty-password
conn1 = pymssql.connect(
    server='SQL01',
    user='user',
    password='',
    database='mydatabase',
)

# ruleid: python-pymssql-empty-password
conn2 = _mssql.connect(
    server='SQL01',
    user='user',
    password='',
    database='mydatabase'
)

# ruleid: python-pymssql-empty-password
conn3 = pymssql.connect(
    server='SQL01',
    user='user',
    password=pswd,
    database='mydatabase',
)

# ok: python-pymssql-empty-password
conn5 = _mssql.connect(
    server='SQL01',
    user='user',
    password=pswd2,
    database='mydatabase'
)

# ok: python-pymssql-empty-password
conn6 = _mssql.connect(
    server='SQL01',
    user='user',
    password=os.env['pswd2'],
    database='mydatabase'
)

# ok: python-pymssql-empty-password
conn7 = _mssql.connect(
    server='SQL01',
    user='user',
    password=os.getenv('secret'),
    database='mydatabase'
)

import os
from couchbase.cluster import Cluster, ClusterOptions
from couchbase_core.cluster import PasswordAuthenticator

# ruleid: python-couchbase-hardcoded-secret
cluster = Cluster('couchbase://localhost', ClusterOptions(PasswordAuthenticator('username', 'password')))

my_pass = "hardcoded"
# ruleid: python-couchbase-hardcoded-secret
PasswordAuthenticator('username', my_pass)

# ok: python-couchbase-hardcoded-secret
cluster = Cluster('couchbase://localhost', ClusterOptions(PasswordAuthenticator('username', get_pass())))

# ok: python-couchbase-hardcoded-secret
PasswordAuthenticator('username', '')

# ok: python-couchbase-hardcoded-secret
PasswordAuthenticator('username', os.env['pass'])

# ok: python-couchbase-hardcoded-secret
PasswordAuthenticator('username', os.getenv(''))

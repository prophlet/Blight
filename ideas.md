# Client hash verification

An issue that most botnets have is client spam. An attacker will use something like a python script to spam invalid clients to an endpoint.
We can fix this by issuing the client a hashed string. The client will then need to crack the hash through brute force by just trying combinations.
Only once the client hash is computed can the client connect. If someone's spawning thousands of threads to spam the client, there won't be enough CPU
resources to crack the hash across all 1000 threads.
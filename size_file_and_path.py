import os
from os.path import getsize, join

# for root, dirs, files in os.walking(''):
#     total_size = sum(getsize(join(root, name)) for name in files)
#     print(root, total_size)

dir_sizes = dict()

for root, dirs, files in os.walk('', topdown=False):
    size = sum(getsize(join(root, f))for f in files)
    size += sum(dir_sizes[join(root, d)]for d in dirs)
    dir_sizes[root] = size

for path, total_size in sorted(dir_sizes.items(), key=lambda x:[0]):
    print(path, sizeof_fmt(total_size)) # type: ignore
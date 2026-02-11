# -----------------
import os
# -----------------
def create_directory(dirname):
    """Creates the directory `dirname` if it does not exist."""
    if dirname and not os.path.isdir(dirname):
        os.makedirs(dirname)
# -----------------
def create_file_directory(filename):
    """Creates the directories required to open `filename` if they do not exist."""
    create_directory(os.path.dirname(filename))
# -----------------
def prefixate(path, prefix, depth=0):
    """Adds a prefix to the filename described by `path`, prefixing at depth `depth`.

    Examples:

    ```python
    prefixate("foo/bar", "bar") -> "foo/barbar"
    prefixate("foo/bar/but", "bar", 1) -> "for/barbar/but"
    ```
    """
    if prefix is not None:
        if depth <= 0:
            return os.path.join(os.path.dirname(path), '{}{}'.format(prefix, os.path.basename(path)))
        return os.path.join(prefixate(os.path.dirname(path), prefix, depth-1), os.path.basename(path))
    return path
# -----------------
def ospath_multisplit(path):
    """Returns the list of the successive dirs of `path`. Ends with the basename of `path`."""
    dirname, basename = os.path.split(path)
    if dirname:
        return ospath_multisplit(dirname) + [basename]
    return [basename]
# -----------------
def ospath_multijoin(plist):
    """Joins the elements of `plist` into a path, using `os.path`."""
    if len(plist) > 1:
        return os.path.join(plist[0], ospath_multijoin(plist[1:]))
    return plist[0]
# -----------------
def flatten_path(path):
    """Replaces all the directory traversing characters of `path` by underscores."""
    return '_'.join(ospath_multisplit(path))
# -----------------
def deprefixate(path):
    """Removes the first dirname of `path`."""
    return ospath_multijoin(ospath_multisplit(path)[1:])
# -----------------

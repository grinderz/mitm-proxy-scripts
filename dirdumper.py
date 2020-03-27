import os
import re

from urllib.parse import unquote
from mitmproxy import ctx, http

forbidden_chars = re.compile("[^\\w\\-\\.]")


class DirDumper:
    def __init__(self):
        self.num = 0

    def load(self, loader):
        loader.add_option(
            "dumpdir", str, "./dump", "Directory to dump all objects into.",
        )
        loader.add_option(
            "dumprequestcontent", bool, False, "Also dump request objects.",
        )

    # We have the problematic situation that a both foo.com/bar
    # and foo.com/bar/baz can be both valid files.
    # However, we cannot create both a folder and a file both called "baz" in the same directory.
    # A possible approach would be using folders for everything and placing __resource__ files in them.
    # While this would be a much consistent structure, it doesn't represent the file system very well.
    # As this view is for visualization purposes only, we took the approach to append [dir] to conflicting folders.
    # to accomplish this, we use a slightly modified version of os.makedirs
    @classmethod
    def makedirs(cls, directory):
        head, tail = os.path.split(directory)
        if not os.path.isdir(head):
            head = cls.makedirs(head)
            directory = os.path.join(head, tail)
        if os.path.isfile(directory):  # our special case - rename current dir
            tail += "[dir]"
            directory = os.path.join(head, tail)
            return cls.makedirs(directory)
        if not os.path.isdir(directory):
            os.mkdir(directory)
        return directory

    @classmethod
    def dump(cls, flow, attr):
        message = getattr(flow, attr)

        # Don't dump empty messages
        if len(message.content) == 0:
            return

        # get host directory name and path directories string
        host = flow.request.host
        if flow.request.port != 80:
            host += "-" + str(flow.request.port)
        pathstr = unquote(
            flow.request.path
                .split("#")[0]  # remove hash
                .split("?")[0]  # remove queryString
        )
        pathstr = os.path.normpath(pathstr).lstrip("./\\")
        if os.path.basename(pathstr) == "":
            pathstr += "__root__"

        host = host.lstrip("./\\")
        if host == "":
            host = "invalid-host"

        dirty_path = [host] + pathstr.replace("\\", "/").split("/")
        paths = []
        for pathelem in dirty_path:

            # replace invalid characters with placeholder
            # (don't remove, that could reintroduce relative path changes)
            pathelem = forbidden_chars.sub('_', pathelem)

            # cut off length
            if len(pathelem) >= 35:
                pathelem = pathelem[:15] + "[..]" + pathelem[15:]

            paths.append(pathelem)

        # If our path is too long, remove directories in the middle
        dir_removed = False
        while sum(len(s) for s in paths) > 150:
            del paths[int(len(paths) / 2)]
            dir_removed = True
        # Add placeholder directory if we removed at least one directory
        if dir_removed:
            splitpos = (len(paths) + 1) / 2
            paths = paths[:splitpos] + ["[...]"] + paths[splitpos:]

        filename = os.path.join(ctx.options.dumpdir, *paths)

        d, filename = os.path.split(filename)
        filename = os.path.join(cls.makedirs(d), filename)

        content = message.content

        # If filename is a directory, rename it.
        if os.path.isdir(filename):
            os.rename(filename, filename + "[dir]")

        # Rename if file already exists and content is different
        filename, ext = os.path.splitext(filename)
        appendix = ""
        if attr == "request":
            filename += " (request)"
        while os.path.isfile(filename + str(appendix) + ext):
            if os.path.getsize(filename + str(appendix) + ext) == len(content):
                with open(filename + str(appendix) + ext, "rb") as f:
                    if f.read() == content:
                        return
            if appendix == "":
                appendix = 1
            else:
                appendix += 1
        filename = filename + str(appendix) + ext

        with open(filename, 'wb') as f:
            f.write(content)

    def request(self, flow: http.HTTPFlow):
        if ctx.options.dumprequestcontent:
            self.dump(flow, "request")

    def response(self, flow: http.HTTPFlow):
        self.dump(flow, "response")


addons = [
    DirDumper()
]

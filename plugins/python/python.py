from __future__ import print_function

import os
import sys
from contextlib import contextmanager
import importlib
import signal
import weakref
from _hexchat_embedded import ffi, lib

VERSION = b'2.0'  # Sync with hexchat.__version__
PLUGIN_NAME = ffi.new('char[]', b'Python')
PLUGIN_DESC = ffi.new('char[]', b'Python %d.%d scripting interface'
                      % (sys.version_info[0], sys.version_info[1]))
PLUGIN_VERSION = ffi.new('char[]', VERSION)
hexchat = None
local_interp = None
hexchat_stdout = None
plugins = set()


if sys.version_info[0] is 2:
    NEWLINE = '\n'
else:
    NEWLINE = ord('\n')


class Stdout:
    def __init__(self):
        self.buffer = bytearray()

    def write(self, string):
        string = string.encode()
        for c in string:
            if c == NEWLINE:
                lib.hexchat_print(lib.ph, bytes(self.buffer))
                self.buffer = bytearray()
            else:
                self.buffer.append(c)

    def isatty(self):
        # FIXME: help() locks app despite this?
        return False


@contextmanager
def redirected_stdout():
    sys.stdout = hexchat_stdout
    sys.stderr = hexchat_stdout
    yield
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__


class Hook:
    def __init__(self, plugin, callback, userdata, is_unload):
        self.is_unload = is_unload
        self.plugin = weakref.proxy(plugin)
        self.callback = callback
        self.userdata = userdata
        self.hexchat_hook = None
        self.handle = ffi.new_handle(weakref.proxy(self))

    def __del__(self):
        print('Removing hook', id(self))
        if self.is_unload is False:
            assert self.hexchat_hook is not None
            lib.hexchat_unhook(lib.ph, self.hexchat_hook)


if sys.version_info[0] is 2:
    def compile_file(data, filename):
        return compile(data, filename, 'exec')
else:
    def compile_file(data, filename):
        return compile(data, filename, 'exec', optimize=2)


class Plugin:
    def __init__(self):
        self.ph = None
        self.name = ''
        self.filename = ''
        self.version = ''
        self.description = ''
        self.hooks = set()
        self.globals = {'__plugin': weakref.proxy(self)}

    def add_hook(self, callback, userdata, is_unload=False):
        hook = Hook(self, callback, userdata, is_unload=is_unload)
        self.hooks.add(hook)
        return hook

    def remove_hook(self, hook, dont_unhook=False):
        for hook in self.hooks:
            if id(hook) == hook:
                ud = hook.userdata
                if dont_unhook is True:
                    hook.is_unload = True
                self.hooks.remove(hook)
                return ud
        else:
            print('Hook not found')

    def loadfile(self, filename):
        with redirected_stdout():
            try:
                self.filename = filename
                with open(filename) as f:
                    data = f.read()
                compiled = compile_file(data, filename)
                exec(compiled, self.globals)

                try:
                    self.name = self.globals['__module_name__']
                    self.version = self.globals.get('__module_version__', '')
                    self.description = self.globals.get('__module_description__', '')
                except KeyError:
                    print('Failed to load module: module information must be set')
                    return False

                self.ph = lib.hexchat_plugingui_add(lib.ph, filename.encode(),
                                                    self.name.encode(),
                                                    self.description.encode(),
                                                    self.version.encode(),
                                                    ffi.NULL)
            except Exception as e:
                print('Failed to load module:', e)
                return False
        return True

    def __del__(self):
        print('unloading', self.filename)
        for hook in self.hooks:
            if hook.is_unload is True:
                with redirected_stdout():
                    try:
                        hook.callback(hook.userdata)
                    except Exception as e:
                        print('Failed to run hook:', e)
        del self.hooks
        if self.ph is not None:
            lib.hexchat_plugingui_remove(lib.ph, self.ph)


if sys.version_info[0] is 2:
    def __decode(string):
        return string
else:
    def __decode(string):
        return string.decode()


# There can be empty entries between non-empty ones so find the actual last value
def wordlist_len(words):
    for i in range(31, 1, -1):
        if ffi.string(words[i]):
            return i
    return 0


def create_wordlist(words):
    size = wordlist_len(words)
    return [__decode(ffi.string(words[i])) for i in range(1, size + 1)]


# This function only exists for compat reasons with the C plugin
# It turns the word list from print hooks into a word_eol list
# This makes no sense to do...
def create_wordeollist(words):
    words = reversed(words)
    last = None
    accum = None
    ret = []
    for word in words:
        if accum is None:
            accum = word
        elif word:
            last = accum
            accum = ' '.join((word, last))
        ret.insert(0, accum)
    return ret


def to_cb_ret(value):
    if value is None:
        return hexchat.EAT_NONE
    else:
        return int(value)


@ffi.def_extern()
def _on_command_hook(word, word_eol, userdata):
    hook = ffi.from_handle(userdata)
    word = create_wordlist(word)
    word_eol = create_wordlist(word_eol)
    with redirected_stdout():
        return to_cb_ret(hook.callback(word, word_eol, hook.userdata))


@ffi.def_extern()
def _on_print_hook(word, userdata):
    hook = ffi.from_handle(userdata)
    word = create_wordlist(word)
    word_eol = create_wordeollist(word)
    with redirected_stdout():
        return to_cb_ret(hook.callback(word, word_eol, hook.userdata))


@ffi.def_extern()
def _on_print_attrs_hook(word, attrs, userdata):
    hook = ffi.from_handle(userdata)
    word = create_wordlist(word)
    word_eol = create_wordeollist(word)
    attr = hexchat.Attribute()
    attr.server_time_utc = attrs.server_time_utc
    with redirected_stdout():
        return to_cb_ret(hook.callback(word, word_eol, attr,  hook.userdata))


@ffi.def_extern()
def _on_server_hook(word, word_eol, userdata):
    hook = ffi.from_handle(userdata)
    word = create_wordlist(word)
    word_eol = create_wordlist(word_eol)
    with redirected_stdout():
        return to_cb_ret(hook.callback(word, word_eol, hook.userdata))


@ffi.def_extern()
def _on_server_attrs_hook(word, word_eol, attrs, userdata):
    hook = ffi.from_handle(userdata)
    word = create_wordlist(word)
    word_eol = create_wordlist(word_eol)
    attr = hexchat.Attribute()
    attr.server_time_utc = attrs.server_time_utc
    with redirected_stdout():
        return to_cb_ret(hook.callback(word, word_eol, attr, hook.userdata))


@ffi.def_extern()
def _on_timer_hook(userdata):
    hook = ffi.from_handle(userdata)
    with redirected_stdout():
        if hook.callback(hook.userdata) is True:
            return 1
        else:
            hook.plugin.remove_hook(hook, dont_unhook=True)
            return 0


@ffi.def_extern()
def _on_say_command(word, word_eol, userdata):
    channel = ffi.string(lib.hexchat_get_info(lib.ph, b'channel'))
    if channel == b'>>python<<':
        python = ffi.string(word_eol[1])
        lib.hexchat_print(lib.ph, b'>>> ' + python)
        try:
            exec_in_interp(python.decode())
        finally:
            return hexchat.EAT_ALL
    return hexchat.EAT_NONE


def load_filename(filename):
    filename = os.path.expanduser(filename)
    if not os.path.isabs(filename):
        configdir = ffi.string(lib.hexchat_get_info(lib.ph, b'configdir')).decode()
        filename = os.path.join(configdir, 'addons', filename)
    if filename and not any(plugin.filename == filename for plugin in plugins):
        plugin = Plugin()
        if plugin.loadfile(filename):
            plugins.add(plugin)
            return True
    return False


def unload_name(name):
    if name:
        for plugin in plugins:
            if name in (plugin.name, plugin.filename,
                        os.path.basename(plugin.filename)):
                plugins.remove(plugin)
                return True
    return False


def reload_name(name):
    if name:
        for plugin in plugins:
            if name in (plugin.name, plugin.filename,
                        os.path.basename(plugin.filename)):
                filename = plugin.filename
                plugins.remove(plugin)
                return load_filename(filename)
    return False


@contextmanager
def change_cwd(path):
    old_cwd = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(old_cwd)


def autoload():
    configdir = ffi.string(lib.hexchat_get_info(lib.ph, b'configdir')).decode()
    addondir = os.path.join(configdir, 'addons')
    with change_cwd(addondir):  # Maintaining old behavior
        for f in os.listdir(addondir):
            if f.endswith('.py'):
                print('Autoloading', f)
                # TODO: Set cwd
                load_filename(os.path.join(addondir, f))


def list_plugins():
    if not plugins:
        print('No python modules loaded')
        return

    lib.hexchat_print(lib.ph, b'Name         Version  Filename             Description')
    lib.hexchat_print(lib.ph, b'----         -------  --------             -----------')
    for plugin in plugins:
        basename = os.path.basename(plugin.filename).encode()
        name = plugin.name.encode()
        version = plugin.version.encode() if plugin.version else b'<none>'
        description = plugin.description.encode() if plugin.description else b'<none>'
        string = b'%-12s %-8s %-20s %-10s' %(name, version, basename, description)
        lib.hexchat_print(lib.ph, string)
    lib.hexchat_print(lib.ph, b'')


def exec_in_interp(python):
    global local_interp

    if not python:
        return

    if local_interp is None:
        local_interp = Plugin()
        local_interp.locals = {}
        local_interp.globals['hexchat'] = hexchat

    with redirected_stdout():
        try:
            ret = eval(python, local_interp.globals, local_interp.locals)
            if ret is not None:
                print(ret)
        except Exception as e:
            print(e)


@ffi.def_extern()
def _on_load_command(word, word_eol, userdata):
    filename = ffi.string(word[2])
    if filename.endswith(b'.py'):
        load_filename(filename.decode())
        return hexchat.EAT_ALL
    return hexchat.EAT_NONE


@ffi.def_extern()
def _on_unload_command(word, word_eol, userdata):
    filename = ffi.string(word[2])
    if filename.endswith(b'.py'):
        unload_name(filename.decode())
        return hexchat.EAT_ALL
    return hexchat.EAT_NONE


@ffi.def_extern()
def _on_reload_command(word, word_eol, userdata):
    filename = ffi.string(word[2])
    if filename.endswith(b'.py'):
        reload_name(filename.decode())
        return hexchat.EAT_ALL
    return hexchat.EAT_NONE


@ffi.def_extern(error=3)  # hexchat.EAT_ALL
def _on_py_command(word, word_eol, userdata):
    subcmd = ffi.string(word[2]).decode().lower()

    if subcmd == 'exec':
        python = ffi.string(word_eol[3]).decode()
        exec_in_interp(python)
    elif subcmd == 'load':
        filename = ffi.string(word[3]).decode()
        load_filename(filename)
    elif subcmd == 'unload':
        name = ffi.string(word[3]).decode()
        unload_name(name)
    elif subcmd == 'reload':
        name = ffi.string(word[3]).decode()
        reload_name(name)
    elif subcmd == 'console':
        lib.hexchat_command(lib.ph, b'QUERY >>python<<')
    elif subcmd == 'list':
        list_plugins()
    elif subcmd == 'about':
        lib.hexchat_print(lib.ph, b'HexChat Python interface version ' + VERSION)
    else:
        lib.hexchat_command(lib.ph, b'HELP PY')

    return hexchat.EAT_ALL


@ffi.def_extern()
def _on_plugin_init(plugin_name, plugin_desc, plugin_version, arg):
    global hexchat
    global hexchat_stdout

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    plugin_name[0] = PLUGIN_NAME
    plugin_desc[0] = PLUGIN_DESC
    plugin_version[0] = PLUGIN_VERSION

    try:
        libdir = ffi.string(lib.hexchat_get_info(lib.ph, b'libdirfs')).decode()
        sys.path.append(libdir)
        hexchat = importlib.import_module('hexchat')
    except (UnicodeDecodeError, ImportError) as e:
        lib.hexchat_print(lib.ph, b'Failed to import module: ' + e.message.encode())
        return 0

    hexchat_stdout = Stdout()
    lib.hexchat_hook_command(lib.ph, b'', 0, lib._on_say_command, ffi.NULL, ffi.NULL)
    lib.hexchat_hook_command(lib.ph, b'LOAD', 0, lib._on_load_command, ffi.NULL, ffi.NULL)
    lib.hexchat_hook_command(lib.ph, b'UNLOAD', 0, lib._on_unload_command, ffi.NULL, ffi.NULL)
    lib.hexchat_hook_command(lib.ph, b'RELOAD', 0, lib._on_reload_command, ffi.NULL, ffi.NULL)
    lib.hexchat_hook_command(lib.ph, b'PY', 0, lib._on_py_command, b'''Usage: /PY LOAD   <filename>
           UNLOAD <filename|name>
           RELOAD <filename|name>
           LIST
           EXEC <command>
           CONSOLE
           ABOUT''', ffi.NULL)

    lib.hexchat_print(lib.ph, b'Python interface loaded')
    autoload()
    return 1


@ffi.def_extern()
def _on_plugin_deinit():
    global local_interp
    global hexchat
    global hexchat_stdout
    global plugins

    plugins = set()
    local_interp = None
    hexchat = None
    hexchat_stdout = None

    del sys.modules['_hexchat']
    del sys.modules['hexchat']
    del sys.modules['xchat']
    del sys.modules['_hexchat_embedded']

    return 1

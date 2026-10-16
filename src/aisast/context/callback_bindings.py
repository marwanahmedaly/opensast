"""Documented callback invocation shapes, selected by qualified imports.

These are possible syntactic calls, not evidence of attacker control or runtime
reachability. The original wrapper's range is retained for argument provenance.
"""
import ast
from aisast.context.framework_bindings import FastAPIBindings


class CallbackBindings:
    APIS = {
        'anyio.to_thread.run_sync': False,
        'asyncio.to_thread': True,
        'starlette.concurrency.run_in_threadpool': True,
        'fastapi.concurrency.run_in_threadpool': True,
    }

    def __init__(self, index):
        self.index = index
        self.framework = FastAPIBindings(index)
        self.cache = {}

    def invocation(self, call, scope):
        key = (id(call), id(scope.node))
        if key in self.cache:
            return self.cache[key]
        self.cache[key] = None
        api = self.framework.qualified(call.func, scope)
        if api not in self.APIS or self.index.resolve(call.func, scope):
            return None
        if self.index.receiver_bindings.bindings(call.func, scope):
            return None
        if not call.args or any(isinstance(a, ast.Starred) for a in call.args):
            return None
        # AnyIO keywords configure the wrapper; they do not bind callback args.
        if any(k.arg is None for k in call.keywords):
            return None
        callback, args = call.args[0], call.args[1:]
        keywords = call.keywords if self.APIS[api] else []
        if isinstance(callback, ast.Call):
            if self.framework.qualified(callback.func, scope) != 'functools.partial':
                return None
            if not callback.args or any(isinstance(a, ast.Starred) for a in callback.args):
                return None
            if any(k.arg is None for k in callback.keywords):
                return None
            args = [*callback.args[1:], *args]
            merged = {k.arg: k for k in callback.keywords}
            merged.update({k.arg: k for k in keywords})
            keywords = list(merged.values())
            callback = callback.args[0]
        # Reject parameters/reassignments used as callable identities. Bound
        # self methods and qualified local definitions use the existing index.
        if self.index.receiver_bindings.bindings(callback, scope):
            return None
        if isinstance(callback, ast.Name):
            current = scope
            while current:
                arguments = getattr(current.node, 'args', None)
                if arguments and any(a.arg == callback.id for a in
                    [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]):
                    return None
                current = current.parent
        if not self.index.resolve(callback, scope):
            return None
        invoked = ast.copy_location(ast.Call(func=callback, args=args, keywords=keywords), call)
        invoked._callback_api = api
        self.cache[key] = invoked
        return invoked

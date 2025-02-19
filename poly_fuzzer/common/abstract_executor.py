import inspect
import time
import sys


class AbstractExecutor:
    '''
        
    # The `AbstractExecutor` class is a Python class that provides functionality for executing a program
    # module and tracking code coverage.
    '''
    def __init__(self, program_module):
        self.program_module = program_module
        self.module_name = program_module.__name__
        self.func_name = inspect.getmodule(program_module).__name__
        self.file_name = inspect.getsourcefile(program_module)
        self._full_coverage = []
        self._coverage = set()

    def _execute_input(self, input):
        exceptions = 0
        try:
            sys.settrace(self.trace_function)
            start_time = time.time()
            #print(f"Input to be executed: {input}")
            output = self.program_module(input)
            end_time = time.time()
            execution_time = end_time - start_time
            sys.settrace(None)
        except Exception as e:
            exceptions += 1
            end_time = time.time()
            execution_time = end_time - start_time
            sys.settrace(None)

        self._coverage = set(self._full_coverage)

        return exceptions, execution_time, self._coverage

    def trace_function(self, frame, event, arg):

        if event == "line":
            # Print information about the current line being executed

            filename = frame.f_code.co_filename
            line_number = frame.f_lineno
            # Check if the file being executed matches the desired module
            code_obj = frame.f_code
            module = inspect.getmodule(code_obj)

            if module is not None:
                module_name = module.__name__

                if self.module_name in filename or self.func_name == module_name:

                    # Add the executed line to the set
                    self._full_coverage.append(line_number)
        return self.trace_function

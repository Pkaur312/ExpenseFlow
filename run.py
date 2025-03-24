import multiprocessing
import os
import sys
from time import sleep

def run_backend():
    os.chdir('backend')
    os.system('python3 app.py')

def run_frontend():
    os.chdir('Frontend')
    os.system('python3 app.py')

if __name__ == '__main__':
    # Start backend process
    backend = multiprocessing.Process(target=run_backend)
    backend.start()
    print("Started backend server on http://127.0.0.1:5001")
    
    # Wait a bit for backend to initialize
    sleep(2)
    
    # Start frontend process
    frontend = multiprocessing.Process(target=run_frontend)
    frontend.start()
    print("Started frontend server on http://127.0.0.1:5100")
    
    print("\nExpenseFlow is running!")
    print("Access the application at: http://127.0.0.1:5100")
    print("Press Ctrl+C to stop both servers")
    
    try:
        backend.join()
        frontend.join()
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        backend.terminate()
        frontend.terminate()
        backend.join()
        frontend.join()
        print("Servers stopped.") 
from project import create_app

if __name__ == '__main__':
  app = create_app()
  app.run(host = '127.0.0.1', port = 8000, debug=False) #Changed boolean value of debug from True to False to disable debugging (addition js: added host to run on local machine 127.0.0.1 fix CWE-605)

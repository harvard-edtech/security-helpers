# Steps to Prevent Damage

### How to Scan for Shai Hulud

1. Allow `scanForWorm.py` to execute on your system: `chmod +x scanForWorm.py`
2. Run with the path to the top-level folder for an npm project (drag and drop works): `python scanForWorm.py /path/to/project`

### Clean Your Computer

Clear your npm cache: `npm cache clean --force`

Remove all `node_modules/` folders on your machine:

1. Navigate to a folder that contains all your projects
2. Run `find . -type d -name "node_modules" -prune -exec rm -rf {} +`
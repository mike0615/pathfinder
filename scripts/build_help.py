"""One canonical JSON source generates repository help."""
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
topics = json.loads((root / 'pathfinder/help.json').read_text())
content = '# Pathfinder help\n\nGenerated from pathfinder/help.json.\n\n' + '\n\n'.join('## '+t['title']+'\n\n'+t['body'] for t in topics) + '\n'
(root / 'HELP.md').write_text(content)

import pytest

from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


@pytest.mark.parametrize(
  "statement, download_trait",
  [
    (
      "curl -O https://downloads.rclone.org/rclone-current-osx-amd64.zip",
      (
        "curl -O https://downloads.rclone.org/rclone-current-osx-amd64.zip",
        {
          "dst": "rclone-current-osx-amd64.zip",
          "src": "https://downloads.rclone.org/rclone-current-osx-amd64.zip",
        },
      ),
    ),
    (
      'curl -X POST "http://localhost:5572/rc/noop?potato=1&sausage=2"',
      (
        'curl -X POST "http://localhost:5572/rc/noop?potato=1&sausage=2"',
        {"dst": None, "src": "http://localhost:5572/rc/noop?potato=1&sausage=2"},
      ),
    ),
    (
      'curl --data "potato=1" --data "sausage=2" http://localhost:5572/rc/noop',
      (
        'curl --data "potato=1" --data "sausage=2" http://localhost:5572/rc/noop',
        {"src": "http://localhost:5572/rc/noop", "dst": None},
      ),
    ),
    (
      'curl --data "potato=1" --data "sausage=2" "http://localhost:5572/rc/noop?rutabaga=3&sausage=4"',
      (
        'curl --data "potato=1" --data "sausage=2" "http://localhost:5572/rc/noop?rutabaga=3&sausage=4"',
        {"src": "http://localhost:5572/rc/noop?rutabaga=3&sausage=4", "dst": None},
      ),
    ),
    (
      'curl -H "Content-Type: application/json" -X POST -d \'{"potato":2,"sausage":1}\' http://localhost:5572/rc/noop',
      (
        'curl -H "Content-Type: application/json" -X POST -d \'{"potato":2,"sausage":1}\' http://localhost:5572/rc/noop',
        {"src": "http://localhost:5572/rc/noop", "dst": None},
      ),
    ),
    (
      'curl -H "Content-Type: application/json" -X POST -d \'{"potato":2,"sausage":1}\' "http://localhost:5572/rc/noop?rutabaga=3&potato=4"',
      (
        'curl -H "Content-Type: application/json" -X POST -d \'{"potato":2,"sausage":1}\' "http://localhost:5572/rc/noop?rutabaga=3&potato=4"',
        {"src": "http://localhost:5572/rc/noop?rutabaga=3&potato=4", "dst": None},
      ),
    ),
  ],
)
def test_curl_extraction(statement, download_trait):
    deobfuscator = BatchDeobfuscator()
    deobfuscator.interpret_curl(statement)
    if download_trait is None:
        assert len(deobfuscator.traits["download"]) == 0
    else:
        assert len(deobfuscator.traits["download"]) == 1
        assert deobfuscator.traits["download"][0] == download_trait

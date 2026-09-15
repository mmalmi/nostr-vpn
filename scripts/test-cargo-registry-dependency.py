#!/usr/bin/env python3
import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('dependency', pathlib.Path(__file__).with_name('verify-cargo-registry-dependency.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PublishedDependencyTests(unittest.TestCase):
    def test_registry_sources_are_exact_and_workspace_metadata_is_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'src').mkdir()
            manifest = b'[package]\nname = "fixture"\nversion = "1.0.0"\n'
            source = b'pub fn value() -> u8 { 1 }\n'
            (root / 'Cargo.toml').write_bytes(manifest)
            (root / 'src/lib.rs').write_bytes(source)
            archive = root / 'fixture.crate'
            files = {'Cargo.toml.orig': manifest, 'src/lib.rs': source,
                     'Cargo.toml': b'normalized manifest', 'Cargo.lock': b'old lock',
                     '.cargo_vcs_info.json': b'old source revision'}
            with tarfile.open(archive, 'w:gz') as tar:
                for name, payload in files.items():
                    info = tarfile.TarInfo('fixture-1.0.0/' + name)
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
            def verify(names=None):
                return module.verify('fixture', '1.0.0', root, archive, list(files) if names is None else names)
            self.assertEqual(verify(), 2)
            (root / 'src/lib.rs').write_bytes(b'pub fn value() -> u8 { 2 }\n')
            with self.assertRaisesRegex(ValueError, 'source differs'):
                verify()
            (root / 'src/lib.rs').write_bytes(source)
            (root / 'Cargo.toml').write_bytes(manifest + b'\n[features]\nchanged = []\n')
            with self.assertRaisesRegex(ValueError, 'source differs'):
                verify()
            (root / 'Cargo.toml').write_bytes(manifest)
            with self.assertRaisesRegex(ValueError, 'file lists differ'):
                verify(list(files) + ['src/extra.rs'])
            with self.assertRaisesRegex(ValueError, 'file lists differ'):
                verify([name for name in files if name != 'src/lib.rs'])
            (root / 'src/lib.rs').unlink()
            (root / 'src/lib.rs').symlink_to(root / 'Cargo.toml')
            with self.assertRaisesRegex(ValueError, 'source differs'):
                verify()


if __name__ == '__main__':
    unittest.main()

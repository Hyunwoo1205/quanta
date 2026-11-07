#!/usr/bin/env python3
"""Bind one native, source-specific A03 candidate to a bounded Docker archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile


ARCHIVE_NAME = 'candidate-image.tar'
METADATA_NAME = 'candidate-image.json'
MAX_ARCHIVE = 2 * 1024**3
MAX_JSON = 64 * 1024
CONFIG_FIELDS = ('Entrypoint', 'Cmd', 'WorkingDir', 'Env', 'Labels', 'User', 'Healthcheck', 'Volumes', 'StopSignal')
OCI_INDEX = 'application/vnd.oci.image.index.v1+json'
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
SHA = re.compile(r'[0-9a-f]{64}\Z')
SOURCE = re.compile(r'[0-9a-f]{40}\Z')


def image_ref(source_sha):
    if not isinstance(source_sha, str) or not SOURCE.fullmatch(source_sha):
        raise ValueError('Invalid candidate Quanta source SHA')
    return 'quanta/a03-armv8a:' + source_sha


def validate_metadata(value, source_sha):
    fields = {'schema_version', 'source_sha', 'archive_sha256', 'archive_bytes',
              'image_ref', 'config_sha256', 'binary_sha256'}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['source_sha'] != source_sha or value['image_ref'] != image_ref(source_sha)
            or type(value['archive_bytes']) is not int or not 0 < value['archive_bytes'] <= MAX_ARCHIVE
            or not all(isinstance(value[name], str) and SHA.fullmatch(value[name])
                       for name in ('archive_sha256', 'config_sha256', 'binary_sha256'))):
        raise ValueError('Invalid source-specific ARMv8-A image metadata')
    return value


def open_regular(path, limit):
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('Candidate image path cannot cross symlinks')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    stream = os.fdopen(fd, 'rb')
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
        stream.close()
        raise ValueError('Candidate must be a bounded regular file')
    return stream


def read_metadata(directory, source_sha):
    if (not directory.is_dir() or directory.is_symlink()
            or {p.name for p in directory.iterdir()} != {ARCHIVE_NAME, METADATA_NAME}):
        raise ValueError('Candidate directory must contain precisely the two native artifact files')
    with open_regular(directory / METADATA_NAME, 2048) as stream:
        return validate_metadata(json.load(stream), source_sha)


def archive_image(stream, expected_tag):
    """Check the Docker and OCI tables describe the same single ARM64 image."""
    stream.seek(0)
    with tarfile.open(fileobj=stream, mode='r:') as archive:
        entries = {}
        for member in archive:
            path = PurePosixPath(member.name)
            if (len(entries) >= 256 or member.name in entries or path.is_absolute()
                    or str(path) != member.name or '..' in path.parts or '\\' in member.name
                    or not (member.isdir() or member.isfile())):
                raise ValueError('Unexpected Docker archive member')
            entries[member.name] = member

        def raw_json(name):
            member = entries.get(name)
            if member is None or not member.isfile() or not 0 < member.size <= MAX_JSON:
                raise ValueError('Missing or oversized image metadata member')
            with archive.extractfile(member) as file:
                return file.read(MAX_JSON + 1)

        docker = json.loads(raw_json('manifest.json'))
        if (not isinstance(docker, list) or len(docker) != 1
                or docker[0].get('RepoTags') != [expected_tag]):
            raise ValueError('Candidate archive must contain only the source-specific tag')
        if 'repositories' in entries:
            repositories = json.loads(raw_json('repositories'))
            repository, tag = expected_tag.split(':')
            if set(repositories) != {repository} or set(repositories[repository]) != {tag}:
                raise ValueError('Candidate legacy repository table contains another tag')
        index = json.loads(raw_json('index.json'))
        if (index.get('schemaVersion') != 2 or index.get('mediaType') not in (None, OCI_INDEX)
                or not isinstance(index.get('manifests'), list) or len(index['manifests']) != 1):
            raise ValueError('Candidate archive requires one OCI platform manifest')
        descriptor = index['manifests'][0]
        annotations = descriptor.get('annotations')
        names = {expected_tag, 'docker.io/' + expected_tag}
        reference = expected_tag.rsplit(':', 1)[1]
        if (not isinstance(annotations, dict) or annotations.get('io.containerd.image.name') not in names
                or annotations.get('org.opencontainers.image.ref.name') not in names | {None, reference}):
            raise ValueError('Candidate OCI index would import a different image tag')

        def blob(desc, media):
            digest = desc.get('digest')
            if (not isinstance(digest, str) or not digest.startswith('sha256:')
                    or not SHA.fullmatch(digest[7:]) or desc.get('mediaType') != media):
                raise ValueError('Invalid candidate image descriptor')
            name = 'blobs/sha256/' + digest[7:]
            raw = raw_json(name)
            if len(raw) != desc.get('size') or hashlib.sha256(raw).hexdigest() != digest[7:]:
                raise ValueError('Candidate image metadata does not match descriptor')
            return name, json.loads(raw)

        _, manifest = blob(descriptor, OCI_MANIFEST)
        config_name, config = blob(manifest['config'], OCI_CONFIG)
        layers = manifest.get('layers')
        rootfs = config.get('rootfs')
        if (manifest.get('schemaVersion') != 2 or manifest.get('mediaType') not in (None, OCI_MANIFEST)
                or docker[0].get('Config') != config_name or config.get('architecture') != 'arm64'
                or config.get('os') != 'linux' or not isinstance(config.get('config'), dict)
                or not isinstance(layers, list) or not isinstance(rootfs, dict) or rootfs.get('type') != 'layers'
                or not isinstance(rootfs.get('diff_ids'), list) or not layers
                or len(rootfs['diff_ids']) != len(layers)
                or not all(isinstance(x, str) and x.startswith('sha256:') and SHA.fullmatch(x[7:])
                           for x in rootfs['diff_ids'])):
            raise ValueError('Candidate archive must contain one coherent native Linux ARM64 image')
        layer_paths = []
        for layer in layers:
            digest = layer.get('digest', '')
            if (not isinstance(digest, str) or not digest.startswith('sha256:') or not SHA.fullmatch(digest[7:])
                    or layer.get('urls')):
                raise ValueError('Invalid candidate layer digest')
            path = 'blobs/sha256/' + digest[7:]
            if path not in entries or not entries[path].isfile() or entries[path].size != layer.get('size'):
                raise ValueError('Missing candidate layer bytes')
            layer_paths.append(path)
        if docker[0].get('Layers') != layer_paths:
            raise ValueError('Candidate Docker and OCI layer tables differ')
        return descriptor, config, manifest['config']['digest']


def check_archive(stream, metadata):
    if os.fstat(stream.fileno()).st_size != metadata['archive_bytes']:
        raise ValueError('Candidate image archive size differs from native CI')
    if hashlib.file_digest(stream, 'sha256').hexdigest() != metadata['archive_sha256']:
        raise ValueError('Candidate image archive hash differs from native CI')
    descriptor, config, config_digest = archive_image(stream, metadata['image_ref'])
    if config_digest != 'sha256:' + metadata['config_sha256']:
        raise ValueError('Candidate image configuration hash differs from native CI')
    return descriptor, config, config_digest


def check_loaded(inspected, metadata, descriptor, config, config_digest):
    if (inspected.get('Architecture') != 'arm64' or inspected.get('Os') != 'linux'
            or metadata['image_ref'] not in (inspected.get('RepoTags') or [])):
        raise ValueError('Loaded candidate architecture or exact tag differs')
    image_id = inspected.get('Id')
    actual_descriptor = inspected.get('Descriptor')
    if actual_descriptor is None:
        if image_id != config_digest:
            raise ValueError('Loaded candidate configuration identity differs')
    elif (image_id != descriptor['digest'] or not isinstance(actual_descriptor, dict)
          or any(actual_descriptor.get(key) != descriptor[key] for key in ('digest', 'mediaType', 'size'))):
        raise ValueError('Loaded candidate platform manifest identity differs')
    rootfs = inspected.get('RootFS') or {}
    if rootfs.get('Type') != 'layers' or rootfs.get('Layers') != config['rootfs']['diff_ids']:
        raise ValueError('Loaded candidate ordered layer DiffIDs differ')
    actual_config = inspected.get('Config') or {}
    for key in CONFIG_FIELDS:
        if (actual_config.get(key) or None) != (config['config'].get(key) or None):
            raise ValueError('Loaded candidate runtime configuration differs at ' + key)
    return {'proof_method': 'native_ci_archive_manifest_and_config', 'daemon_image_id': image_id,
            'locked_platform_manifest_digest': descriptor['digest'],
            'locked_platform_manifest_bytes': descriptor['size'], 'locked_config_digest': config_digest,
            'ordered_rootfs_diff_ids_match': True, 'runtime_config_projection_matches': True}


def load_candidate(directory, source_sha, *, run=subprocess.run):
    metadata = read_metadata(directory, source_sha)
    reference = metadata['image_ref']
    with open_regular(directory / ARCHIVE_NAME, MAX_ARCHIVE) as stream:
        descriptor, config, config_digest = check_archive(stream, metadata)
        inspect = ['docker', 'image', 'inspect', reference]
        inspected = run(inspect, capture_output=True, timeout=30, check=False)
        already_loaded = inspected.returncode == 0
        if not already_loaded:
            if b'No such image' not in inspected.stderr and b'No such object' not in inspected.stderr:
                raise RuntimeError('Could not determine whether the candidate tag is already loaded')
            stream.seek(0)
            load = run(['docker', 'image', 'load', '--quiet'], stdin=stream,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300, check=False)
            if load.returncode:
                raise RuntimeError('Docker did not load the verified native CI archive')
            inspected = run(inspect, capture_output=True, timeout=30, check=True)
    images = json.loads(inspected.stdout)
    if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
        raise ValueError('Docker did not inspect exactly one candidate image')
    proof = check_loaded(images[0], metadata, descriptor, config, config_digest)
    proof['already_loaded_identical_image'] = already_loaded
    return metadata, proof


def record(directory, source_sha, binary_sha):
    reference = image_ref(source_sha)
    with open_regular(directory / ARCHIVE_NAME, MAX_ARCHIVE) as stream:
        size = os.fstat(stream.fileno()).st_size
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        _, _, config_digest = archive_image(stream, reference)
    metadata = validate_metadata({'schema_version': 1, 'source_sha': source_sha,
        'image_ref': reference, 'archive_bytes': size, 'archive_sha256': digest,
        'config_sha256': config_digest[7:], 'binary_sha256': binary_sha}, source_sha)
    with (directory / METADATA_NAME).open('x', encoding='utf-8') as stream:
        json.dump(metadata, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['record'])
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--binary-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(record(args.directory, args.source_sha, args.binary_sha256), sort_keys=True))


if __name__ == '__main__':
    main()

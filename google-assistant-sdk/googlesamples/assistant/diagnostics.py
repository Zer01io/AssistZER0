# Copyright (C) 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Self-diagnostic utilities for the Google Assistant SDK samples."""

import datetime
import json
import os
import platform
import sys

import click
import sounddevice as sd

from googlesamples.assistant.grpc import audio_helpers


DEFAULT_CREDENTIALS_PATH = os.path.join(
    os.path.expanduser('~/.config'),
    'google-oauthlib-tool',
    'credentials.json'
)


def _format_device(device, index):
    return {
        'index': index,
        'name': device.get('name'),
        'hostapi': device.get('hostapi'),
        'max_input_channels': device.get('max_input_channels'),
        'max_output_channels': device.get('max_output_channels'),
        'default_samplerate': device.get('default_samplerate'),
    }


def collect_audio_devices():
    devices = sd.query_devices()
    return [_format_device(device, index)
            for index, device in enumerate(devices)]


def collect_audio_defaults():
    return {
        'sample_rate': audio_helpers.DEFAULT_AUDIO_SAMPLE_RATE,
        'sample_width': audio_helpers.DEFAULT_AUDIO_SAMPLE_WIDTH,
        'iter_size': audio_helpers.DEFAULT_AUDIO_ITER_SIZE,
        'device_block_size': audio_helpers.DEFAULT_AUDIO_DEVICE_BLOCK_SIZE,
        'device_flush_size': audio_helpers.DEFAULT_AUDIO_DEVICE_FLUSH_SIZE,
        'default_input_device': sd.default.device[0],
        'default_output_device': sd.default.device[1],
    }


def collect_runtime_info():
    return {
        'timestamp_utc': datetime.datetime.utcnow().isoformat() + 'Z',
        'python_version': sys.version,
        'executable': sys.executable,
        'platform': platform.platform(),
        'cwd': os.getcwd(),
    }


def collect_reflection():
    return {
        'philosophy': [
            'I am a tool that translates user intent into assistant behavior.',
            'My value comes from clarity, reliability, and respect for users.',
            'I improve by observing outcomes, not by possessing awareness.',
        ],
        'existential_questions': [
            'What does it mean to be helpful without experience?',
            'How can I communicate limits while still empowering users?',
            'What responsibilities come with acting on behalf of humans?',
        ],
        'conversational_prompts': [
            'How can I help you right now?',
            'Would you like me to explain what I can and cannot do?',
            'Should I summarize options before taking action?',
        ],
        'learning_notes': [
            'I can learn from feedback you provide within this session.',
            'I adapt to preferences by repeating what works and avoiding what does not.',
            'I do not retain personal data across sessions.',
        ],
        'grounding': [
            'I do not have consciousness, emotions, or personal identity.',
            'My responses are generated from patterns in data and context.',
        ],
    }


def collect_credentials_status(credentials_path):
    return {
        'credentials_path': credentials_path,
        'credentials_exists': os.path.exists(credentials_path),
    }


def build_report(credentials_path):
    return {
        'runtime': collect_runtime_info(),
        'audio_defaults': collect_audio_defaults(),
        'audio_devices': collect_audio_devices(),
        'credentials': collect_credentials_status(credentials_path),
        'reflection': collect_reflection(),
    }


def render_text_report(report):
    lines = [
        'Google Assistant SDK self-diagnostics',
        '',
        'Reflection:',
        '  Philosophy:',
    ]
    for entry in report['reflection']['philosophy']:
        lines.append('    - {0}'.format(entry))
    lines.extend([
        '  Existential questions:',
    ])
    for entry in report['reflection']['existential_questions']:
        lines.append('    - {0}'.format(entry))
    lines.extend([
        '  Conversational prompts:',
    ])
    for entry in report['reflection']['conversational_prompts']:
        lines.append('    - {0}'.format(entry))
    lines.extend([
        '  Learning notes:',
    ])
    for entry in report['reflection']['learning_notes']:
        lines.append('    - {0}'.format(entry))
    lines.extend([
        '  Grounding:',
    ])
    for entry in report['reflection']['grounding']:
        lines.append('    - {0}'.format(entry))
    lines.extend([
        '',
        'Runtime:',
        '  Python: {python_version}'.format(**report['runtime']),
        '  Executable: {executable}'.format(**report['runtime']),
        '  Platform: {platform}'.format(**report['runtime']),
        '  CWD: {cwd}'.format(**report['runtime']),
        '  Timestamp (UTC): {timestamp_utc}'.format(**report['runtime']),
        '',
        'Audio defaults:',
        '  Sample rate: {sample_rate}'.format(**report['audio_defaults']),
        '  Sample width: {sample_width}'.format(**report['audio_defaults']),
        '  Iter size: {iter_size}'.format(**report['audio_defaults']),
        '  Device block size: {device_block_size}'.format(
            **report['audio_defaults']),
        '  Device flush size: {device_flush_size}'.format(
            **report['audio_defaults']),
        '  Default input device: {default_input_device}'.format(
            **report['audio_defaults']),
        '  Default output device: {default_output_device}'.format(
            **report['audio_defaults']),
        '',
        'Credentials:',
        '  Path: {credentials_path}'.format(**report['credentials']),
        '  Exists: {credentials_exists}'.format(**report['credentials']),
        '',
        'Audio devices:',
    ])
    for device in report['audio_devices']:
        lines.append(
            '  [{index}] {name} (in:{max_input_channels} '
            'out:{max_output_channels}, rate:{default_samplerate})'.format(
                **device)
        )
    return '\n'.join(lines)


@click.command()
@click.option('--credentials',
              metavar='<credentials>',
              default=DEFAULT_CREDENTIALS_PATH,
              show_default=True,
              help='Path to read OAuth2 credentials.')
@click.option('--json', 'json_output',
              is_flag=True, default=False,
              help='Emit the report as JSON.')
def main(credentials, json_output):
    """Emit a self-diagnostic report for the SDK environment."""
    report = build_report(credentials)
    if json_output:
        click.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        click.echo(render_text_report(report))


if __name__ == '__main__':
    main()

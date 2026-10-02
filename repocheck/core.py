from __future__ import annotations

import ast
import json
import re
import shlex
import subprocess
import tempfile
import zipfile
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Optional
import html
import hashlib
import tomllib
import venv

IGNORE_DIRS = {'.git', '.venv', 'venv', '.repocheck', '__pycache__', 'node_modules', 'build', 'dist'}
COMMAND_STARTERS = ('python', 'python3', 'bash', 'sh', 'make', 'torchrun', 'accelerate')
SEVERITY_WEIGHT = {'high': 15, 'medium': 8, 'low': 3}


@dataclass(slots=True)
class Evidence:
    file: str
    line_start: int
    line_end: int
    snippet: str
    confidence: float = 1.0


@dataclass(slots=True)
class CommandCandidate:
    command: str
    source: str
    kind: str
    score: float
    entrypoint: Optional[str] = None
    exists: bool = True
    issues: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    params: dict = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = ""


@dataclass(slots=True)
class RunRecipe:
    command: str
    env_requirements: dict = field(default_factory=dict)
    config_files: list[str] = field(default_factory=list)
    expected_outputs: list[str] = field(default_factory=list)
    missing_inputs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SmokeStepResult:
    name: str
    command: str
    success: bool
    return_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(slots=True)
class SmokeResult:
    mode: str
    success: bool
    steps: list[SmokeStepResult] = field(default_factory=list)
    environment_path: Optional[str] = None


@dataclass(slots=True)
class ProjectManifest:
    source: str
    root_path: str
    language: str = 'python'
    frameworks: list[str] = field(default_factory=list)
    config_system: Optional[str] = None
    dependency_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    shell_scripts: list[str] = field(default_factory=list)
    docs_files: list[str] = field(default_factory=list)
    python_files: list[str] = field(default_factory=list)
    notebook_files: list[str] = field(default_factory=list)
    ci_files: list[str] = field(default_factory=list)
    docker_files: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    commands: list[CommandCandidate] = field(default_factory=list)
    readme_path: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass(slots=True)
class AuditReport:
    manifest: ProjectManifest
    findings: list[Finding]
    score: int
    risk_summary: dict
    generated_at: str
    mode: str
    analysis: dict = field(default_factory=dict)
    recipe: Optional[RunRecipe] = None
    smoke: Optional[SmokeResult] = None
    cache_hit: bool = False


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def read_text(path):
    try:
        return Path(path).read_text(encoding='utf-8-sig')
    except UnicodeDecodeError:
        return Path(path).read_text(encoding='latin-1')


def relative_path(path, root):
    return str(Path(path).resolve().relative_to(Path(root).resolve()))


def make_evidence(path, line_number, snippet=None, line_end=None, confidence=1.0):
    lines = read_text(path).splitlines() if Path(path).exists() else []
    if line_end is None:
        line_end = line_number
    if snippet is None:
        snippet = lines[line_number - 1].strip() if line_number in range(1, len(lines) + 1) else ""
    return Evidence(file=str(path), line_start=line_number, line_end=line_end, snippet=snippet, confidence=confidence)


def normalize_key(key):
    return key.strip().lstrip('-').replace('-', '_').replace(' ', '_').lower()


def coerce_scalar(value):
    raw = value.strip().strip('"').strip("'")
    if raw.lower() in {'true', 'false'}:
        return raw.lower() == 'true'
    if raw.lower() in {'none', 'null'}:
        return None
    if re.fullmatch(r'-?[0-9]+', raw):
        return int(raw)
    if re.fullmatch(r'-?[0-9]+\.[0-9]+', raw):
        return float(raw)
    return raw


def is_probable_absolute_path(text):
    candidate = text.strip().strip('"').strip("'")
    if candidate.startswith('/') and '://' not in candidate:
        return True
    if len(candidate) in range(3, 2048) and candidate[1] == ':' and candidate[2] in {'\\', '/'}:
        return True
    return False


def split_command(command):
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def is_git_url(source):
    return source.startswith('http://') or source.startswith('https://') or source.startswith('git@')


def resolve_source(source):
    candidate = Path(source).expanduser()
    if candidate.exists() and candidate.is_dir():
        return candidate.resolve(), str(candidate.resolve()), False
    if candidate.exists() and candidate.is_file() and candidate.suffix.lower() == '.zip':
        target = Path(tempfile.mkdtemp(prefix='repocheck_zip_'))
        with zipfile.ZipFile(candidate, 'r') as archive:
            archive.extractall(target)
        roots = [item for item in target.iterdir() if item.is_dir()]
        root = roots[0] if len(roots) == 1 else target
        return root.resolve(), str(candidate.resolve()), True
    if is_git_url(source):
        target = Path(tempfile.mkdtemp(prefix='repocheck_git_'))
        subprocess.run(['git', 'clone', '--depth', '1', source, str(target)], check=True, capture_output=True, text=True)
        return target.resolve(), source, True
    raise FileNotFoundError(f'Could not resolve source: {source}')


def iter_repo_files(root):
    for path in sorted(Path(root).rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        yield path


def extract_params(command):
    params = {}
    tokens = split_command(command)
    index = 0
    while index in range(len(tokens)):
        token = tokens[index]
        if token.startswith('--') and '=' in token:
            key, value = token.split('=', 1)
            params[normalize_key(key)] = coerce_scalar(value)
        elif token.startswith('--'):
            next_index = index + 1
            if next_index in range(len(tokens)) and not tokens[next_index].startswith('-'):
                params[normalize_key(token)] = coerce_scalar(tokens[next_index])
                index += 1
            else:
                params[normalize_key(token)] = True
        elif '=' in token and token and token[0].islower():
            key, value = token.split('=', 1)
            params[normalize_key(key)] = coerce_scalar(value)
        index += 1
    return params


def classify_command(command):
    lowered = command.lower()
    if 'train' in lowered:
        return 'train'
    if 'eval' in lowered or 'test' in lowered:
        return 'eval'
    if 'prep' in lowered or 'download' in lowered or 'data' in lowered:
        return 'prepare'
    return 'other'


def command_entrypoint(command):
    tokens = split_command(command)
    if not tokens:
        return None
    lead = tokens[0]
    if lead in {'python', 'python3', 'torchrun', 'accelerate'}:
        for token in tokens[1:]:
            if token.endswith('.py'):
                return token
    if lead in {'bash', 'sh'} and len(tokens) in range(2, 2048):
        return tokens[1]
    if lead == 'make' and len(tokens) in range(2, 2048):
        return f'make:{tokens[1]}'
    if lead.endswith('.py'):
        return lead
    return None


def make_command_candidate(command, source, root, evidence):
    kind = classify_command(command)
    entrypoint = command_entrypoint(command)
    score = 10
    issues = []
    exists = True
    if source.startswith('README'):
        score += 20
    if kind == 'train':
        score += 25
    elif kind == 'eval':
        score += 15
    elif kind == 'prepare':
        score += 10
    if entrypoint and not entrypoint.startswith('make:'):
        exists = (Path(root) / entrypoint).exists()
        if exists:
            score += 20
        else:
            score -= 30
            issues.append('Referenced file does not exist')
    if any(is_probable_absolute_path(str(value)) for value in extract_params(command).values() if isinstance(value, str)):
        score -= 10
        issues.append('Command includes an absolute path')
    return CommandCandidate(command=command, source=source, kind=kind, score=score, entrypoint=entrypoint, exists=exists, issues=issues, evidence=[evidence], params=extract_params(command))


def parse_readme_commands(path, root):
    text = read_text(path)
    commands = []
    block = []
    in_block = False
    block_start = 1
    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith('```'):
            if in_block:
                for offset, line in enumerate(block, start=0):
                    candidate = line.strip()
                    if any(candidate.startswith(prefix) for prefix in COMMAND_STARTERS):
                        evidence = make_evidence(path, block_start + offset, snippet=candidate)
                        commands.append(make_command_candidate(candidate, 'README code block', root, evidence))
            in_block = not in_block
            block = []
            block_start = line_number + 1
            continue
        if in_block:
            block.append(raw)
    return commands, text


def parse_line_commands(path, root, source):
    commands = []
    for line_number, raw in enumerate(read_text(path).splitlines(), start=1):
        candidate = raw.strip()
        if not candidate or candidate.startswith('#'):
            continue
        if any(candidate.startswith(prefix) for prefix in COMMAND_STARTERS):
            commands.append(make_command_candidate(candidate, source, root, make_evidence(path, line_number, snippet=candidate)))
    return commands


def parse_workflow_commands(path, root):
    commands = []
    lines = read_text(path).splitlines()
    index = 0
    while index in range(len(lines)):
        raw = lines[index]
        stripped = raw.strip()
        if stripped.startswith('run:'):
            value = stripped.split(':', 1)[1].strip()
            if value and value != '|':
                commands.append(make_command_candidate(value, f'workflow:{path.name}', root, make_evidence(path, index + 1, snippet=value)))
            else:
                index += 1
                while index in range(len(lines)) and lines[index].startswith(' ' * 10):
                    candidate = lines[index].strip()
                    if any(candidate.startswith(prefix) for prefix in COMMAND_STARTERS):
                        commands.append(make_command_candidate(candidate, f'workflow:{path.name}', root, make_evidence(path, index + 1, snippet=candidate)))
                    index += 1
        index += 1
    return commands


def scan_repository(source_label, root):
    manifest = ProjectManifest(source=source_label, root_path=str(root))
    commands = []
    readme_text = ""
    for path in iter_repo_files(root):
        rel = relative_path(path, root)
        lower_name = path.name.lower()
        if lower_name.startswith('readme'):
            manifest.readme_path = rel
            manifest.docs_files.append(rel)
            new_commands, readme_text = parse_readme_commands(path, root)
            commands.extend(new_commands)
        elif path.suffix.lower() == '.py':
            manifest.python_files.append(rel)
        elif path.suffix.lower() in {'.md', '.rst'}:
            manifest.docs_files.append(rel)
        elif path.suffix.lower() in {'.sh', '.bash'}:
            manifest.shell_scripts.append(rel)
            commands.extend(parse_line_commands(path, root, f'script:{path.name}'))
        elif lower_name in {'requirements.txt', 'pyproject.toml', 'environment.yml', 'environment.yaml', 'setup.py'}:
            manifest.dependency_files.append(rel)
        elif path.suffix.lower() == '.ipynb':
            manifest.notebook_files.append(rel)
        elif path.suffix.lower() in {'.yaml', '.yml', '.json', '.toml'}:
            if 'config' in rel.lower() or 'configs' in rel.lower():
                manifest.config_files.append(rel)
        if '.github/workflows' in rel.replace('\\', '/').lower():
            manifest.ci_files.append(rel)
            commands.extend(parse_workflow_commands(path, root))
        if lower_name == 'makefile':
            commands.extend(parse_line_commands(path, root, 'Makefile'))
        if lower_name == 'dockerfile':
            manifest.docker_files.append(rel)
    manifest.commands = commands
    manifest.metadata['readme_text'] = readme_text
    manifest.metadata['docker_available'] = bool(manifest.docker_files)
    manifest.metadata['notebooks_present'] = bool(manifest.notebook_files)
    return manifest


def attribute_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = attribute_name(node.value)
        return f'{base}.{node.attr}' if base else node.attr
    return ""


def constant_value(node):
    if isinstance(node, ast.Constant):
        return node.value
    return None


class Inspector(ast.NodeVisitor):
    def __init__(self, path, source):
        self.path = Path(path)
        self.source = source
        self.imports = set()
        self.has_main = False
        self.arg_defaults = {}
        self.click_defaults = {}
        self.hydra = {}
        self.seed = {'python': [], 'numpy': [], 'torch': [], 'cuda': []}
        self.cudnn_deterministic = []
        self.cudnn_benchmark = []
        self.dataloader_calls = []
        self.dataloader_worker_init = []
        self.absolute_paths = []
        self.env_paths = []
        self.relative_paths = []
        self.cuda_usage = []
        self.checkpoint_loads = []

    def ev(self, node):
        snippet = ast.get_source_segment(self.source, node) or ""
        line_end = getattr(node, 'end_lineno', node.lineno)
        return Evidence(file=str(self.path), line_start=node.lineno, line_end=line_end, snippet=snippet.strip(), confidence=1.0)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name.split('.', 1)[0])

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module.split('.', 1)[0])

    def visit_If(self, node):
        text = ast.get_source_segment(self.source, node.test) or ""
        if '__name__' in text and '__main__' in text:
            self.has_main = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            name = attribute_name(decorator.func) if isinstance(decorator, ast.Call) else attribute_name(decorator)
            if name.endswith('hydra.main') and isinstance(decorator, ast.Call):
                for keyword in decorator.keywords:
                    if keyword.arg in {'config_path', 'config_name'}:
                        self.hydra[keyword.arg] = constant_value(keyword.value)
            if name.endswith('click.option') and isinstance(decorator, ast.Call):
                flags = [constant_value(arg) for arg in decorator.args if isinstance(constant_value(arg), str)]
                flag = next((item for item in flags if item and item.startswith('--')), None)
                if flag:
                    default_value = None
                    for keyword in decorator.keywords:
                        if keyword.arg == 'default':
                            default_value = constant_value(keyword.value)
                    self.click_defaults[normalize_key(flag)] = {'value': default_value, 'evidence': self.ev(decorator)}
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            name = attribute_name(target)
            if name.endswith('cudnn.deterministic') and constant_value(node.value) is True:
                self.cudnn_deterministic.append(self.ev(node))
            if name.endswith('cudnn.benchmark') and constant_value(node.value) is False:
                self.cudnn_benchmark.append(self.ev(node))
        self.generic_visit(node)


    def visit_Call(self, node):
        name = attribute_name(node.func)
        if name.endswith('add_argument'):
            flags = [constant_value(arg) for arg in node.args if isinstance(constant_value(arg), str)]
            flag = next((item for item in flags if item and item.startswith('--')), None)
            if flag:
                default_value = None
                for keyword in node.keywords:
                    if keyword.arg == 'default':
                        default_value = constant_value(keyword.value)
                self.arg_defaults[normalize_key(flag)] = {'value': default_value, 'evidence': self.ev(node)}
        if name in {'random.seed', 'seed'}:
            self.seed['python'].append(self.ev(node))
        if name in {'np.random.seed', 'numpy.random.seed'}:
            self.seed['numpy'].append(self.ev(node))
        if name in {'torch.manual_seed', 'seed_everything'}:
            self.seed['torch'].append(self.ev(node))
        if name in {'torch.cuda.manual_seed_all', 'torch.cuda.manual_seed'}:
            self.seed['cuda'].append(self.ev(node))
        if name.endswith('DataLoader'):
            self.dataloader_calls.append(self.ev(node))
            for keyword in node.keywords:
                if keyword.arg == 'worker_init_fn':
                    self.dataloader_worker_init.append(self.ev(node))
        if 'cuda' in name or name.endswith('.cuda'):
            self.cuda_usage.append(self.ev(node))
        if name in {'torch.load', 'load_state_dict'} or name.endswith('from_pretrained'):
            self.checkpoint_loads.append(self.ev(node))
        self.generic_visit(node)

    def visit_Constant(self, node):
        if not isinstance(node.value, str):
            return
        text = node.value
        if is_probable_absolute_path(text):
            self.absolute_paths.append(self.ev(node))
        elif '${' in text or '$HOME' in text or '$DATA' in text:
            self.env_paths.append(self.ev(node))
        elif text.startswith('./data') or text.startswith('data/') or text.startswith('../data'):
            self.relative_paths.append(self.ev(node))


def inspect_python_file(path):
    source = read_text(path)
    tree = ast.parse(source)
    inspector = Inspector(path, source)
    inspector.visit(tree)
    return inspector


def inspect_repository(manifest):
    info = []
    for rel in manifest.python_files:
        info.append(inspect_python_file(Path(manifest.root_path) / rel))
    frameworks = set()
    entrypoints = []
    for inspector in info:
        imports = inspector.imports
        if 'torch' in imports:
            frameworks.add('pytorch')
        if 'hydra' in imports or inspector.hydra:
            frameworks.add('hydra')
        if 'click' in imports or inspector.click_defaults:
            frameworks.add('click')
        if 'argparse' in imports or inspector.arg_defaults:
            frameworks.add('argparse')
        rel = relative_path(inspector.path, manifest.root_path)
        name = Path(rel).name.lower()
        if inspector.has_main or name in {'train.py', 'main.py', 'run.py', 'eval.py'}:
            entrypoints.append(rel)
    for command in manifest.commands:
        if command.entrypoint and not command.entrypoint.startswith('make:'):
            entrypoints.append(command.entrypoint)
    manifest.frameworks = sorted(frameworks)
    manifest.entrypoints = sorted(dict.fromkeys(entrypoints))
    if 'hydra' in frameworks:
        manifest.config_system = 'hydra'
    elif any(item.arg_defaults for item in info):
        manifest.config_system = 'argparse'
    elif any(item.click_defaults for item in info):
        manifest.config_system = 'click'
    elif manifest.config_files:
        manifest.config_system = 'yaml'
    return info


def parse_yaml_flat(path):
    records = []
    stack = []
    for line_number, raw in enumerate(read_text(path).splitlines(), start=1):
        if not raw.strip() or raw.strip().startswith('#'):
            continue
        indent = len(raw) - len(raw.lstrip(' '))
        stripped = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if stripped.startswith('- ') or ':' not in stripped:
            continue
        key, value = stripped.split(':', 1)
        key = key.strip().strip('"').strip("'")
        value = value.strip()
        parts = [item[1] for item in stack]
        dotted = '.'.join(parts + [key]) if parts else key
        if value:
            records.append({'key': normalize_key(dotted), 'value': coerce_scalar(value), 'source': str(path), 'source_type': 'config', 'evidence': make_evidence(path, line_number, snippet=stripped)})
        else:
            stack.append((indent, key))
    return records


def dependency_lines(path):
    rel = Path(path).name.lower()
    text = read_text(path)
    if rel == 'requirements.txt':
        return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith('#')]
    if rel == 'pyproject.toml':
        data = tomllib.loads(text)
        project = data.get('project', {})
        items = list(project.get('dependencies', []))
        requires_python = project.get('requires-python')
        return items + ([f'python {requires_python}'] if requires_python else [])
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith('#')]


def parse_dependency_findings(manifest):
    unpinned = []
    python_declared = []
    cuda_documented = []
    for rel in manifest.dependency_files:
        path = Path(manifest.root_path) / rel
        for line_number, raw in enumerate(read_text(path).splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            lowered = line.lower()
            if 'python' in lowered and any(char.isdigit() for char in lowered):
                python_declared.append(make_evidence(path, line_number, snippet=line))
            if 'cuda' in lowered or 'cudnn' in lowered:
                cuda_documented.append(make_evidence(path, line_number, snippet=line))
            if rel.endswith('requirements.txt') and '==' not in line and '@' not in line and not line.startswith('-e '):
                unpinned.append(make_evidence(path, line_number, snippet=line))
    readme_text = manifest.metadata.get('readme_text', '').lower()
    if 'python ' in readme_text:
        python_declared.append(make_evidence(Path(manifest.root_path) / manifest.readme_path, 1, snippet='README mentions Python')) if manifest.readme_path else None
    if 'cuda' in readme_text or 'cudnn' in readme_text:
        cuda_documented.append(make_evidence(Path(manifest.root_path) / manifest.readme_path, 1, snippet='README mentions CUDA')) if manifest.readme_path else None
    return unpinned, python_declared, cuda_documented


def collect_analysis(manifest, inspectors):
    unpinned, python_declared, cuda_documented = parse_dependency_findings(manifest)
    records = []
    seed = {'python': [], 'numpy': [], 'torch': [], 'cuda': []}
    absolute_paths = []
    env_paths = []
    relative_paths = []
    cuda_required = []
    checkpoint_loads = []
    dataloader_calls = []
    dataloader_worker_init = []
    cudnn_deterministic = []
    cudnn_benchmark = []
    for inspector in inspectors:
        seed['python'].extend(inspector.seed['python'])
        seed['numpy'].extend(inspector.seed['numpy'])
        seed['torch'].extend(inspector.seed['torch'])
        seed['cuda'].extend(inspector.seed['cuda'])
        absolute_paths.extend(inspector.absolute_paths)
        env_paths.extend(inspector.env_paths)
        relative_paths.extend(inspector.relative_paths)
        cuda_required.extend(inspector.cuda_usage)
        checkpoint_loads.extend(inspector.checkpoint_loads)
        dataloader_calls.extend(inspector.dataloader_calls)
        dataloader_worker_init.extend(inspector.dataloader_worker_init)
        cudnn_deterministic.extend(inspector.cudnn_deterministic)
        cudnn_benchmark.extend(inspector.cudnn_benchmark)
        for key, payload in inspector.arg_defaults.items():
            records.append({'key': key, 'value': payload['value'], 'source': str(inspector.path), 'source_type': 'code', 'evidence': payload['evidence']})
        for key, payload in inspector.click_defaults.items():
            records.append({'key': key, 'value': payload['value'], 'source': str(inspector.path), 'source_type': 'code', 'evidence': payload['evidence']})
    for rel in manifest.config_files:
        path = Path(manifest.root_path) / rel
        if path.suffix.lower() in {'.yaml', '.yml'}:
            records.extend(parse_yaml_flat(path))
    for command in manifest.commands:
        for key, value in command.params.items():
            records.append({'key': key, 'value': value, 'source': command.source, 'source_type': 'command', 'evidence': command.evidence[0]})
    readme_text = manifest.metadata.get('readme_text', '').lower()
    minimal_example = any(item.source.startswith('README') and item.exists for item in manifest.commands)
    data_documented = any(word in readme_text for word in ['download', 'dataset', 'data root', 'data_root', 'prepare'])
    weights_documented = 'checkpoint' in readme_text or 'weights' in readme_text or 'pretrained' in readme_text
    best_command = sorted(manifest.commands, key=lambda item: item.score, reverse=True)[0] if manifest.commands else None

    conflicts = []
    grouped = {}
    for record in records:
        grouped.setdefault(record['key'], []).append(record)
    for key, items in grouped.items():
        values = {json.dumps(item['value'], sort_keys=True, default=str) for item in items}
        source_types = {item['source_type'] for item in items}
        if len(values) in range(2, 4096) and len(source_types) in range(2, 4096):
            conflicts.append({'key': key, 'items': items})
    return {
        'unpinned': unpinned,
        'python_declared': python_declared,
        'cuda_documented': cuda_documented,
        'cuda_required': cuda_required,
        'seed': seed,
        'absolute_paths': absolute_paths,
        'env_paths': env_paths,
        'relative_paths': relative_paths,
        'checkpoint_loads': checkpoint_loads,
        'dataloader_calls': dataloader_calls,
        'dataloader_worker_init': dataloader_worker_init,
        'cudnn_deterministic': cudnn_deterministic,
        'cudnn_benchmark': cudnn_benchmark,
        'minimal_example': minimal_example,
        'data_documented': data_documented,
        'weights_documented': weights_documented,
        'records': records,
        'conflicts': conflicts,
        'best_command': best_command,
    }


def augment_analysis(manifest, analysis, inspectors):
	grouped = {}
	for record in analysis['records']:
		grouped.setdefault(record['key'], []).append(record)
	analysis['grouped_records'] = grouped
	analysis['config_keys'] = sorted({record['key'] for record in analysis['records'] if record['source_type'] == 'config'})

	entrypoint_param_map = {}
	for inspector in inspectors:
		rel = relative_path(inspector.path, manifest.root_path)
		entrypoint_param_map[rel] = {
			'keys': sorted(set(inspector.arg_defaults).union(inspector.click_defaults)),
			'hydra': inspector.hydra,
		}
	analysis['entrypoint_param_map'] = entrypoint_param_map

	repeated_keys = []
	for key, items in grouped.items():
		source_types = {item['source_type'] for item in items}
		if len(source_types) >= 2:
			repeated_keys.append({'key': key, 'items': items})
	analysis['repeated_keys'] = repeated_keys

	signals = {
		'data_version': [],
		'data_split': [],
		'data_checksum': [],
		'data_url': [],
		'auto_download': [],
		'checksum_validation': [],
		'priority_docs': [],
		'resolved_config': [],
		'eval_threshold': [],
		'eval_postprocess': [],
		'eval_sampling': [],
	}
	seen = set()
	paths = []
	for rel in manifest.docs_files + manifest.shell_scripts + manifest.python_files:
		if rel in seen:
			continue
		seen.add(rel)
		path = Path(manifest.root_path) / rel
		if path.exists():
			paths.append(path)

	url_pattern = re.compile(r'https?://\\S+')
	version_pattern = re.compile(r'\\bv?\\d+(?:\\.\\d+){0,2}\\b')
	for path in paths:
		is_script_source = path.suffix.lower() in {'.py', '.sh', '.bash'}
		for line_number, raw in enumerate(read_text(path).splitlines(), start=1):
			stripped = raw.strip()
			lowered = stripped.lower()
			if not stripped:
				continue
			evidence = make_evidence(path, line_number, snippet=stripped)
			if url_pattern.search(stripped):
				signals['data_url'].append(evidence)
			if ('dataset' in lowered or 'data' in lowered) and ('version' in lowered or 'release' in lowered or version_pattern.search(lowered)):
				signals['data_version'].append(evidence)
			if 'split' in lowered or ('train' in lowered and ('val' in lowered or 'test' in lowered)) or 'fold' in lowered:
				signals['data_split'].append(evidence)
			if any(token in lowered for token in ['sha256', 'sha-256', 'md5', 'checksum']):
				signals['data_checksum'].append(evidence)
			if is_script_source and any(token in lowered for token in ['wget ', 'curl ', 'gdown', 'download', 'requests.get', 'urlretrieve']):
				signals['auto_download'].append(evidence)
			if any(token in lowered for token in ['hashlib', 'sha256', 'md5', 'checksum failed', 'hash mismatch', 'verification failed', 'invalid checksum']):
				signals['checksum_validation'].append(evidence)
			if any(token in lowered for token in ['priority', 'precedence', 'override order', 'command line overrides', 'cli overrides', 'single source of truth']):
				signals['priority_docs'].append(evidence)
			if any(token in lowered for token in ['resolved config', 'effective config', 'save_config', 'dump_config', 'omegaconf.save', 'save resolved', 'dump resolved', 'config dump']):
				signals['resolved_config'].append(evidence)
			if any(token in lowered for token in ['threshold', 'topk', 'top-k', 'cutoff']):
				signals['eval_threshold'].append(evidence)
			if any(token in lowered for token in ['postprocess', 'post-process', 'post process', 'nms', 'decode']):
				signals['eval_postprocess'].append(evidence)
			if any(token in lowered for token in ['sampling', 'sample ', 'samples ', 'trials', 'repeat', 'repeats', 'monte carlo']):
				signals['eval_sampling'].append(evidence)

	analysis.update(signals)
	analysis['eval_commands'] = [evidence for command in manifest.commands if command.kind == 'eval' for evidence in command.evidence]

	eval_scripts = []
	for rel in manifest.python_files + manifest.shell_scripts:
		lowered = rel.lower()
		if any(token in lowered for token in ['eval', 'metric', 'metrics', 'score', 'test']):
			eval_scripts.append(make_evidence(Path(manifest.root_path) / rel, 1, snippet=rel))
	analysis['eval_scripts'] = eval_scripts
	return analysis

def evidence_list(*items):
	out = []
	for item in items:
		if isinstance(item, list):
			out.extend(item)
		elif item is not None:
			out.append(item)
	return out

def build_findings(manifest, analysis):
	findings = []
	seed_total = sum(len(items) for items in analysis['seed'].values())
	if analysis['unpinned']:
		findings.append(Finding('ENV001', 'high', 'Dependency versions are not pinned', 'At least one dependency file leaves package versions floating.', analysis['unpinned'], 'Pin dependencies with exact versions in requirements.txt or pyproject.toml.'))
	if not analysis['python_declared']:
		findings.append(Finding('ENV002', 'high', 'Python version is not declared', 'The repository does not clearly declare the Python runtime version.', [], 'Declare Python in pyproject.toml, environment.yml, or README.'))
	if analysis['cuda_required'] and not analysis['cuda_documented']:
		findings.append(Finding('CUDA001', 'medium', 'CUDA or cuDNN version is undocumented', 'Code touches CUDA but the expected CUDA stack is not documented.', analysis['cuda_required'], 'Document tested CUDA and cuDNN versions in README or dependency files.'))
	if not manifest.entrypoints:
		findings.append(Finding('RUN001', 'high', 'No runnable entrypoint found', 'The audit could not identify a reliable training or evaluation entrypoint.', [], 'Expose a clear python script, shell entrypoint, or Make target in README.'))
	elif analysis['best_command'] and not analysis['best_command'].exists:
		findings.append(Finding('RUN001', 'high', 'Best command references a missing file', 'The highest scoring command points at a file that does not exist.', analysis['best_command'].evidence, 'Fix the README or script command so it references a real file.'))
	if not analysis['minimal_example']:
		findings.append(Finding('DOC001', 'medium', 'README lacks a minimal executable example', 'The documentation does not provide a trustworthy minimal command to run.', [], 'Add a shortest-path command for training or evaluation to README.'))
	if analysis['absolute_paths']:
		findings.append(Finding('DATA001', 'high', 'Hardcoded absolute data path detected', 'The code includes dataset or artifact paths tied to a local machine.', analysis['absolute_paths'], 'Replace absolute paths with CLI flags or environment variables.'))
	if (analysis['absolute_paths'] or analysis['env_paths']) and not analysis['data_documented']:
		findings.append(Finding('DATA002', 'medium', 'Data acquisition steps are undocumented', 'The repository references dataset locations but does not explain how to prepare them.', evidence_list(analysis['absolute_paths'], analysis['env_paths']), 'Document download and preprocessing steps in README.'))
	if seed_total == 0:
		findings.append(Finding('SEED001', 'high', 'No reproducibility seed found', 'The code does not appear to set Python, NumPy, or Torch seeds.', [], 'Set random, NumPy, and Torch seeds near the main entrypoint.'))
	elif analysis['dataloader_calls'] and not analysis['dataloader_worker_init']:
		findings.append(Finding('SEED002', 'medium', 'DataLoader worker seed is missing', 'The project uses DataLoader but does not set worker_init_fn or equivalent seeding.', analysis['dataloader_calls'], 'Seed DataLoader workers or provide a deterministic generator.'))
	elif analysis['cuda_required'] and (not analysis['cudnn_deterministic'] or not analysis['cudnn_benchmark']):
		findings.append(Finding('SEED002', 'medium', 'cuDNN determinism is incomplete', 'CUDA is used but deterministic and benchmark flags are not fully configured.', analysis['cuda_required'], 'Set cudnn.deterministic = True and cudnn.benchmark = False when determinism matters.'))
	if analysis['conflicts']:
		evidence = [item['items'][0]['evidence'] for item in analysis['conflicts']]
		findings.append(Finding('CFG001', 'medium', 'README, config, and code values disagree', 'At least one parameter resolves to different values across docs, code, and config files.', evidence, 'Document the winning value and reduce duplicate configuration layers.'))
	if analysis['checkpoint_loads'] and not analysis['weights_documented']:
		findings.append(Finding('ART001', 'medium', 'Checkpoint source is undocumented', 'The code loads checkpoints but the repository does not explain where they come from.', analysis['checkpoint_loads'], 'Document checkpoint provenance or provide a download URL.'))
	return findings

def has_safe_default(analysis, keys):
	grouped = analysis.get('grouped_records', {})
	for key in keys:
		for item in grouped.get(key, []):
			if item['source_type'] not in {'code', 'config'}:
				continue
			value = item['value']
			if isinstance(value, str):
				if value and not is_probable_absolute_path(value):
					return True, item['evidence']
			elif value not in {None, False, ''}:
				return True, item['evidence']
	return False, None

def validate_recipe(manifest, analysis, recipe=None):
	result = {'entrypoint': None, 'unknown_params': [], 'missing_inputs': [], 'evidence': []}
	if not recipe:
		return result

	entrypoint = command_entrypoint(recipe.command)
	if not entrypoint and manifest.entrypoints:
		entrypoint = manifest.entrypoints[0]
	result['entrypoint'] = entrypoint

	recipe_params = extract_params(recipe.command)
	entrypoint_info = analysis.get('entrypoint_param_map', {}).get(entrypoint, {})
	supported_keys = set(entrypoint_info.get('keys', []))
	hydra_meta = entrypoint_info.get('hydra') or {}
	if hydra_meta:
		supported_keys.update({'config_name', 'config_path'})
	config_keys = set(analysis.get('config_keys', []))

	unknown_params = []
	for key in recipe_params:
		if key in {'h', 'help', 'dry_run'}:
			continue
		if key in supported_keys or key in config_keys:
			continue
		if hydra_meta and key in {'config', 'config_name', 'config_path'}:
			continue
		unknown_params.append(key)
	result['unknown_params'] = sorted(dict.fromkeys(unknown_params))

	if analysis.get('best_command') and analysis['best_command'].command == recipe.command:
		result['evidence'].extend(analysis['best_command'].evidence)

	data_keys = ('data_root', 'data.root', 'data_dir', 'dataset_root', 'dataset_path')
	weight_keys = ('checkpoint', 'checkpoint_path', 'weights', 'weights_path', 'pretrained', 'ckpt', 'model_path')
	config_selection_keys = ('config', 'config_name', 'config_path')

	needs_data_input = analysis['absolute_paths'] or analysis['env_paths'] or any(key in analysis.get('grouped_records', {}) for key in data_keys)
	if needs_data_input and not any(key in recipe_params for key in data_keys):
		ok, evidence = has_safe_default(analysis, data_keys)
		if not ok:
			result['missing_inputs'].append('data root')
			if evidence:
				result['evidence'].append(evidence)

	if analysis['checkpoint_loads'] and not any(key in recipe_params for key in weight_keys):
		ok, evidence = has_safe_default(analysis, weight_keys)
		if not ok:
			result['missing_inputs'].append('checkpoint or weights path')
			if evidence:
				result['evidence'].append(evidence)

	needs_config = manifest.config_system in {'hydra', 'yaml'} and len(manifest.config_files) >= 2
	if needs_config and not any(key in recipe_params for key in config_selection_keys):
		ok, evidence = has_safe_default(analysis, config_selection_keys)
		hydra_default = bool(hydra_meta.get('config_name'))
		if not ok and not hydra_default:
			result['missing_inputs'].append('config selection')
			if evidence:
				result['evidence'].append(evidence)

	return result

def extra_findings(manifest, analysis, recipe=None):
	findings = []
	recipe_validation = analysis.get('recipe_validation') or validate_recipe(manifest, analysis, recipe)

	if recipe and (recipe_validation['unknown_params'] or recipe_validation['missing_inputs']):
		details = []
		if recipe_validation['unknown_params']:
			details.append('unparsed parameters: ' + ', '.join(recipe_validation['unknown_params']))
		if recipe_validation['missing_inputs']:
			details.append('missing closed-over inputs: ' + ', '.join(recipe_validation['missing_inputs']))
		findings.append(Finding('RUN002', 'high', 'Suggested minimal command is not actually runnable', 'The recommended minimal command is not self-contained: ' + '; '.join(details) + '.', recipe_validation['evidence'], 'Make the suggested command parser-valid and include required config, data, and checkpoint inputs or provide safe defaults.'))

	data_missing = []
	if not analysis['data_version']:
		data_missing.append('dataset version')
	if not analysis['data_split']:
		data_missing.append('split definition')
	if not analysis['data_checksum']:
		data_missing.append('checksum')
	if not analysis['data_url']:
		data_missing.append('download URL')
	if not analysis['auto_download']:
		data_missing.append('auto-download script')
	elif not analysis['checksum_validation']:
		data_missing.append('checksum validation failure handling')
	if data_missing:
		findings.append(Finding('DATA003', 'medium', 'Dataset version and integrity details are incomplete', 'The repository does not fully define dataset provenance and integrity: missing ' + ', '.join(data_missing) + '.', evidence_list(analysis['data_version'], analysis['data_split'], analysis['data_checksum'], analysis['data_url'], analysis['auto_download'])[:5], 'Document dataset version, split, checksum, download URL, and add script-level hash verification with a clear failure message.'))

	if analysis['repeated_keys'] and (not analysis['priority_docs'] or not analysis['resolved_config']):
		missing = []
		if not analysis['priority_docs']:
			missing.append('override precedence documentation')
		if not analysis['resolved_config']:
			missing.append('resolved config export')
		evidence = [item['items'][0]['evidence'] for item in analysis['repeated_keys'][:3]]
		findings.append(Finding('CFG002', 'medium', 'Configuration is not a single source of truth', 'Parameters are defined in multiple layers, but ' + ' and '.join(missing) + ' is not clearly established.', evidence, 'Document precedence between README, scripts, and config files, and save the effective resolved config for every run.'))

	eval_missing = []
	if not analysis['eval_commands'] and not analysis['eval_scripts']:
		eval_missing.append('evaluation command or metric script')
	if not analysis['data_split']:
		eval_missing.append('validation or test split')
	if not analysis['eval_threshold']:
		eval_missing.append('threshold or decision rule')
	if not analysis['eval_postprocess']:
		eval_missing.append('post-processing description')
	if not analysis['eval_sampling']:
		eval_missing.append('sampling or repeat count')
	if eval_missing:
		findings.append(Finding('EVAL001', 'medium', 'Evaluation protocol is not reproducible', 'The repository does not fully specify the evaluation protocol: missing ' + ', '.join(eval_missing) + '.', evidence_list(analysis['eval_commands'], analysis['eval_scripts'], analysis['data_split'], analysis['eval_threshold'], analysis['eval_postprocess'], analysis['eval_sampling'])[:5], 'Provide a reproducible evaluation command, metric script, split definition, threshold or decision rule, post-processing settings, and repeat count or sampling procedure.'))

	return findings

def build_recipe(manifest, analysis):
    command = None
    if analysis['best_command']:
        command = analysis['best_command'].command
    elif manifest.entrypoints:
        command = f'python {manifest.entrypoints[0]}'
    if not command:
        return None
    keys = {record['key'] for record in analysis['records']}
    if 'seed' in keys and '--seed' not in command and ' seed=' not in command:
        command += ' --seed 42' if manifest.config_system != 'hydra' else ' seed=42'
    if 'data_root' in keys and 'data-root' not in command and 'data.root' not in command and 'data_root' not in command:
        command += ' --data-root ./data' if manifest.config_system != 'hydra' else ' data.root=./data'
    if 'epochs' in keys and '--epochs' not in command and 'epochs=' not in command and manifest.config_system != 'hydra':
        command += ' --epochs 1'
    missing_inputs = []
    if analysis['absolute_paths'] or analysis['env_paths']:
        missing_inputs.append('dataset files under ./data or an equivalent user-provided path')
    if analysis['checkpoint_loads'] and not analysis['weights_documented']:
        missing_inputs.append('checkpoint or pretrained weights path')
    return RunRecipe(command=command, env_requirements={'frameworks': manifest.frameworks, 'config_system': manifest.config_system}, config_files=manifest.config_files[:5], expected_outputs=['./outputs', './checkpoints'], missing_inputs=missing_inputs)


def score_report(findings):
    score = 100
    summary = {'high': 0, 'medium': 0, 'low': 0}
    for finding in findings:
        summary[finding.severity] += 1
        score -= SEVERITY_WEIGHT[finding.severity]
    return max(score, 0), summary


def command_args(command, env_python=None):
    args = split_command(command)
    if env_python and args and args[0] in {'python', 'python3'}:
        args[0] = str(env_python)
    return args


def internal_path(root, *parts):
    """Keep generated audit data inside the repository, without following links."""
    root = Path(root).resolve()
    path = root
    for part in ('.repocheck', *parts):
        path = path / part
        if path.is_symlink():
            raise ValueError(f'Refusing symlink in audit output path: {path}')
    path.resolve().relative_to(root)
    return path


def run_smoke(manifest, recipe):
    runtime_dir = internal_path(manifest.root_path, 'runtime')
    runtime_dir.mkdir(parents=True, exist_ok=True)
    venv_dir = Path(tempfile.mkdtemp(prefix='smoke_', dir=runtime_dir))
    builder = venv.EnvBuilder(with_pip=False)
    builder.create(venv_dir)
    python_bin = venv_dir / 'Scripts' / 'python.exe'
    if not python_bin.exists():
        python_bin = venv_dir / 'bin' / 'python'
    steps = []
    steps.append(SmokeStepResult('create_venv', str(venv_dir), True, 0, stdout='created', stderr=''))
    help_args = command_args(recipe.command, python_bin)
    if '--help' not in help_args and '-h' not in help_args:
        help_args = help_args + ['--help']
    completed = subprocess.run(help_args, cwd=manifest.root_path, capture_output=True, text=True, timeout=60)
    steps.append(SmokeStepResult('help', ' '.join(help_args), completed.returncode == 0, completed.returncode, stdout=completed.stdout[-2000:], stderr=completed.stderr[-2000:]))
    dry_args = command_args(recipe.command, python_bin)
    if '--dry-run' not in dry_args and '--help' not in dry_args and '-h' not in dry_args:
        dry_args = dry_args + ['--dry-run']
    completed = subprocess.run(dry_args, cwd=manifest.root_path, capture_output=True, text=True, timeout=60)
    steps.append(SmokeStepResult('dry_run', ' '.join(dry_args), completed.returncode == 0, completed.returncode, stdout=completed.stdout[-2000:], stderr=completed.stderr[-2000:]))
    success = all(step.success for step in steps)
    return SmokeResult(mode='smoke', success=success, steps=steps, environment_path=str(venv_dir))


def render_terminal(report):
    lines = []
    lines.append(f'Reproducibility Score: {report.score}/100')
    lines.append(f'Risk Summary: {report.risk_summary.get("high", 0)} high, {report.risk_summary.get("medium", 0)} medium, {report.risk_summary.get("low", 0)} low')
    lines.append(f'Frameworks: {", ".join(report.manifest.frameworks) if report.manifest.frameworks else "unknown"}')
    if report.recipe:
        lines.append('')
        lines.append('Suggested minimal command')
        lines.append(report.recipe.command)
        if report.recipe.missing_inputs:
            lines.append('Missing inputs: ' + '; '.join(report.recipe.missing_inputs))
    if report.findings:
        lines.append('')
        lines.append('Findings')
        for finding in report.findings:
            lines.append(f'[{finding.severity.upper()}] {finding.rule_id}: {finding.title}')
            lines.append(finding.message)
            if finding.evidence:
                first = finding.evidence[0]
                lines.append(f' Evidence: {first.file}:{first.line_start} {first.snippet}')
    if report.smoke:
        lines.append('')
        lines.append(f'Smoke mode: {"passed" if report.smoke.success else "failed"}')
        for step in report.smoke.steps:
            lines.append(f' {step.name}: {step.return_code}')
    return '\n'.join(lines)



def report_payload(report):
    return asdict(report)


def write_json_report(report, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report_payload(report), indent=2, ensure_ascii=False), encoding='utf-8-sig')


def write_cache(report):
    cache_path = internal_path(report.manifest.root_path, 'cache', 'last_report.json')
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(report_payload(report), indent=2, ensure_ascii=False), encoding='utf-8-sig')


def write_html_report(report, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = html.escape(render_terminal(report))
    text = '<!doctype html><html><meta charset="utf-8"><title>RepoCheck Report</title><body><h1>RepoCheck Report</h1><pre>' + body + '</pre></body></html>'
    path.write_text(text, encoding='utf-8-sig')


def audit_source(source, mode='fast', use_cache=True):
	root, label, _temporary = resolve_source(source)
	manifest = scan_repository(label, root)
	inspectors = inspect_repository(manifest)
	analysis = collect_analysis(manifest, inspectors)
	analysis = augment_analysis(manifest, analysis, inspectors)
	recipe = build_recipe(manifest, analysis)
	analysis['recipe_validation'] = validate_recipe(manifest, analysis, recipe)
	findings = build_findings(manifest, analysis)
	findings.extend(extra_findings(manifest, analysis, recipe))
	smoke = run_smoke(manifest, recipe) if mode in {'smoke', 'full'} and recipe else None
	score, summary = score_report(findings)
	report = AuditReport(manifest=manifest, findings=findings, score=score, risk_summary=summary, generated_at=now_iso(), mode=mode, analysis=analysis, recipe=recipe, smoke=smoke, cache_hit=False)
	if use_cache:
		write_cache(report)
	return report


"""
DC3-MWCP Framework command line tool.

Used for running and testing parsers.
"""

import pathlib
import shlex
from typing import Tuple

import pandas
import pytest

import glob
from io import open
import json
import logging
import os
import subprocess
import sys
import traceback

import click
import tabulate

import mwcp
from mwcp import testing, Report
from mwcp.config import settings, report_formats, default_config, user_config, local_config
from mwcp import registry
from mwcp.stix.report_writer import STIXWriter

logger = logging.getLogger("mwcp")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
@click.option("-d", "--debug", is_flag=True, help="Enables DEBUG level logs.")
@click.option("-v", "--verbose", is_flag=True, help="Enables INFO level logs.")
@click.option(
    "--parser-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Optional extra parser directory.",
)
@click.option(
    "--parser-config",
    type=click.Path(exists=True, dir_okay=False),
    help="Optional parser configuration file to use with extra parser directory.",
)
@click.option(
    "--parser-source",
    help="Set a default parsers source to use. If not provided parsers from all sources will be available.",
)
def main(ctx, debug, verbose, parser_dir, parser_config, parser_source):
    # Skip setup if running 'config' command.
    if ctx.invoked_subcommand == "config":
        return

    # Ensure configuration is reloaded
    settings.configure()

    if parser_dir:
        settings.parser_dir = parser_dir
    parser_dir = settings.get("parser_dir")
    if parser_config:
        settings.parser_config_path = parser_config
    parser_config = settings.get("parser_config_path")
    if parser_source:
        settings.parser_source = parser_source
    parser_source = settings.get("parser_source")

    # Setup logging
    mwcp.setup_logging()
    if debug:
        logging.root.setLevel(logging.DEBUG)
    elif verbose:
        logging.root.setLevel(logging.INFO)
    # else let log_config.yaml set log level.

    # Register parsers
    mwcp.register_entry_points()
    if parser_dir:
        mwcp.register_parser_directory(parser_dir, config_file_path=parser_config)
    if parser_source:
        mwcp.set_default_source(parser_source)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="The interface to bind to.")
@click.option("--port", default=8080, show_default=True, help="The port to bind to.")
@click.option("--debug", is_flag=True, help="Show the interactive debugger if errors occur.")
def serve(host, port, debug):
    """Run a server to handle parsing requests."""
    from mwcp.tools import server

    if debug:
        os.environ["FLASK_ENV"] = "development"

    app = server.create_app()
    app.run(host=host, port=port, debug=debug, use_reloader=False)


def _create_config(path: pathlib.Path):
    click.echo(f"Writing: {path.absolute()}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_config.read_text())



@main.group(invoke_without_command=True)
@click.pass_context
def config(ctx):
    """Opens up configuration file for editing."""
    # Defaults to 'edit' if subcommand not provided.
    if not ctx.invoked_subcommand:
        ctx.forward(config_edit)


@config.command("create")
@click.option("-o", "--overwrite", is_flag=True, help="Overwrite existing settings file.")
@click.option("-l", "--local", is_flag=True, help=f"Create local settings file instead of one at {user_config}")
def config_create(overwrite, local):
    """
    Creates a settings file in user directory or current working directory.
    """
    path = local_config if local else user_config
    if path.exists() and not overwrite:
        raise click.UsageError("Settings file already exists and --overwrite was not specified.")
    _create_config(path)


@config.command("edit")
@click.option("-l", "--local", is_flag=True, help=f"Open local settings file instead of one at {user_config}")
def config_edit(local):
    """
    Opens settings file for editing.
    """
    path = local_config if local else user_config
    if not path.exists():
        _create_config(path)
    click.echo(f"Opening {path.absolute()} for editing...")
    if sys.platform == "win32":
        try:
            os.startfile(path, "edit")
        except WindowsError:
            os.startfile(path)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, path])


@config.command("list", context_settings={"ignore_unknown_options": True})
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def config_list(args):
    """
    Lists currently applied settings.
    """
    subprocess.run(["dynaconf", "-i", "mwcp.config.settings", "list", *args])


@main.command("list")
@click.option(
    "-a",
    "--all",
    "all_",
    is_flag=True,
    help="Whether to also include parsers not listed in any parsers configuration file.",
)
@click.option("-j", "--json", "json_", is_flag=True, help="Display as JSON output.")
def list_(all_, json_):
    """Lists registered malware config parsers."""
    descriptions = mwcp.get_parser_descriptions(allow_missing_deps=True, config_only=not all_)
    if json_:
        print(json.dumps(descriptions, indent=4))
    else:
        print(tabulate.tabulate(descriptions, headers=["NAME", "SOURCE", "AUTHOR", "DESCRIPTION"]))


def _parse_parameters(params) -> dict:
    """
    Parses the results from the --parameter option in the `parse` and `test` command.
    Returns a knowledge_base dictionary.
    """
    knowledge_base = {}
    for entry in params:
        key, found, value = entry.partition(":")
        if not found:
            raise click.UsageError(f"Missing ':' in parameter: '{entry}'")
        if value.casefold() == "true":
            value = True
        elif value.casefold() == "false":
            value = False
        else:
            try:
                value = int(value)
            except ValueError:
                pass
        if key in knowledge_base:
            raise click.UsageError(f"'{key}' parameter defined twice.")
        knowledge_base[key] = value
    return knowledge_base


def _print_reports(*reports, format="simple", split=False):
    if format in ("simple", "markdown", "html"):
        for report in reports:
            print(report.as_text(format, split=split))

    elif format == "json":
        results = []
        for report in reports:
            if split:
                results.extend(report.as_json_dict(split=True))
            else:
                results.append(report.as_json_dict())
        print(json.dumps(results, indent=4))

    elif format == "csv":
        # TODO: Determine a more elegant way to handle multiple reports and split/non-split reports
        #   writing to the same stream/df.
        if len(reports) == 1:
            df = reports[0].as_dataframe(split=split)
        else:
            df = pandas.concat([report.as_dataframe(split=split) for report in reports])
        try:
            print(df.to_csv(lineterminator="\n"))
        except TypeError:
            print(df.to_csv(line_terminator="\n"))  # pandas < 2.0

    elif format == "stix":
        writer = STIXWriter()
        # aggregate the report details
        for report in reports:
            report.write_stix(writer)
        print(writer.serialize())

    else:
        raise ValueError(f"Invalid format: {format}")


@main.command()
@click.option(
    "--yara-repo",
    type=click.Path(file_okay=False),
    help="Directory containing YARA signatures used for auto detection.",
)
@click.option(
    "--recursive/--no-recursive",
    default=settings.recursive,
    show_default=True,
    help="Whether to recursively parse unidentified residual files using YARA match. "
         "(Only works if a YARA repo has been provided through command line or configuration)"
)
@click.option(
    "-f", "--format",
    type=click.Choice(report_formats),
    default=settings.report.format,
    show_default=True,
    help="Displays results in another format.",
)
@click.option(
    "--split/--no-split",
    default=settings.report.split,
    show_default=True,
    help="Whether to display results by source file the metadata originates from. "
         "By default, results are only consolidated based on original input file. "
)
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Root output directory to store residual files. (defaults to current directory)",
)
@click.option(
    "--output-files/--no-output-files",
    default=settings.report.output_files,
    show_default=True,
    help="Whether to output files to filesystem."
)
@click.option(
    "--prefix/--no-prefix",
    default=settings.report.md5_prefix,
    show_default=True,
    help="Whether to prefix output filenames with the first 5 characters of the md5. "
         "If turned off, unique files with the same file name will be overwritten."
)
@click.option(
    "--string-report/--no-string-report",
    default=settings.report.string_report,
    show_default=True,
    help="Whether to report decoded strings into a separate external report output "
         "as a supplemental file."
)
@click.option(
    "--include-file-data", "--data/--no-data",
    default=settings.report.include_file_data,
    is_flag=True,
    help="Whether to include file data in serialized results."
)
@click.option(
    "--include-logs", "--logs/--no-logs",
    default=settings.report.include_logs,
    is_flag=True,
    help="Whether to include error and debug logs in the results."
)
@click.option(
    "-p", "--param", "--parameter",
    multiple=True,
    help="External parameters that will get passed through to the parsers using the knowledge_base. "
         "Should be a 'key:value' pair, where 'value' is a string, integer or boolean. "
         "Binary data is not supported, we recommend base64 encoding if the need arises. "
         "(e.g. --param aes_key:secret) "
         "This flag can be provided multiple times for multiple parameters."
)
@click.option(
    "--keep-tmp",
    is_flag=True,
    help="Keep temporary files generated by FileObject.temp_path()"
)
@click.argument("parser", required=True)
@click.argument("input", nargs=-1, type=click.Path())
def parse(
        parser, input, yara_repo, recursive, format, split, output_dir, output_files, prefix, string_report,
        include_file_data, include_logs, param, keep_tmp
):
    """
    Parses given input with given parser.

    \b
    PARSER: Name of parser to run. (or "-" for YARA matching)
    INPUT: One or more input file paths. (Wildcards are allowed).

    \b
    Common usages::
        mwcp parse foo ./malware.bin                          - Run foo parser on ./malware.bin
        mwcp parse foo ./malware.bin --param key:secret       - Run foo parser on ./malware.bin with external knowledge of a secret key to be used by the parser.
        mwcp parse foo ./repo/*                               - Run foo parser on files found in repo directory.
        mwcp parse -f json foo ./malware.bin                  - Run foo parser and display results as json.
        mwcp parse -f csv foo ./repo/* > ./results.csv        - Run foo parser on a directory and output results as a csv file.
        mwcp parse - ./malware.bin --yara-repo=./rules        - Run a parser on ./malware.bin where the parser is detected by YARA.
        mwcp parse - ./malware.bin                            - yara_repo can be omitted if included in configuration.
    """
    knowledge_base = {**_parse_parameters(param), **settings.knowledge_base}

    if yara_repo:
        settings.yara_repo = yara_repo
    if keep_tmp:
        settings.keep_tmp = keep_tmp

    # Python won't process wildcards when used through Windows command prompt.
    if any("*" in path for path in input):
        new_input = []
        for path in input:
            if "*" in path:
                new_input.extend(glob.glob(path))
            else:
                new_input.append(path)
        input = new_input

    input_files = list(filter(os.path.isfile, input))
    output_dir = output_dir or ""

    # Run MWCP
    try:
        reports = []
        for path in input_files:
            config = dict(
                output_directory=os.path.join(output_dir, os.path.basename(path) + settings.report.output_suffix) if output_files else None,
                prefix_output_files=prefix,
                external_strings_report=string_report,
                recursive=recursive,
                knowledge_base=knowledge_base,
                include_file_data=include_file_data,
                include_logs=include_logs,
            )
            if parser == "-":
                parser = None
            logger.info(f"Parsing: {path}")
            # TODO: This is temporary, make real fix.
            if path == "-":
                report = mwcp.run(parser, data=sys.stdin.read().encode(), **config)
            else:
                report = mwcp.run(parser, file_path=path, **config)
            reports.append(report)

        # Print results
        _print_reports(*reports, format=format, split=split)

    except Exception as e:
        error_message = "Error running DC3-MWCP: {}".format(e)
        traceback.print_exc()
        if format == "json":
            print(json.dumps({"errors": [error_message]}))
        else:
            print(error_message)
        sys.exit(1)


@main.command()
@click.option(
    "-t",
    "--testcase-dir",
    type=click.Path(file_okay=False),
    help="Directory containing JSON test case files. (defaults to a "
    '"tests" directory located within the parsers directory)',
)
@click.option(
    "-m",
    "--malware-repo",
    type=click.Path(file_okay=False),
    help="Directory containing malware samples used for testing.",
)
# Arguments used for run test cases.
@click.option(
    "-n", "--nprocs", type=int,
    help="Number of test cases to run simultaneously. [default: 3/4 * logical CPU cores]"
)
# Arguments used to generate and update test cases
@click.option(
    "-u",
    "--update",
    is_flag=True,
    help="Update all stored test cases with newly produced results. "
    "If used with the --add option, this allows the test cases for the added files to "
    "be updated if the file already exists in the test case.",
)
@click.option(
    "-a",
    "--add",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Adds given file to the test case. "
         "(Will first copy file to malware repo if provided.)",
)
@click.option(
    "-i",
    "--add-filelist",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Adds a file of file paths to the test case.",
)
@click.option(
    "-x",
    "--delete",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Deletes given file from the test case. "
         "(Note, this does not delete the file if placed in a malware repo.)",
)
@click.option("-y", "--yes", is_flag=True, help="Auto confirm questions.")
@click.option(
    "-f", "--force", is_flag=True,
    help="Force test case to add/update even when errors are encountered."
)
@click.option(
    "--last-failed", "--lf",
    is_flag=True,
    help="Rerun only the tests that failed at the last run",
)
# Arguments to configure console output
@click.option(
    "-s", "--silent",
    is_flag=True,
    help="Limit output to statement saying whether all tests passed or not."
)
@click.option(
    "--exit-on-first/--no-exit-on-first",
    default=False,
    show_default=True,
    help="Whether to exit on the first failed test case."
)
@click.option(
    "-c", "--command",
    is_flag=True,
    help="Displays the pytest command that would be run, instead of actually running any test "
         "(only applicable for running tests). "
         "This might be helpful for scripting your own advanced testing apparatus."
)
@click.option(
    "--full-diff",
    is_flag=True,
    help="Whether to display a full diff for failed tests. Disables custom unified diff display."
)
@click.option(
    "--yara-repo",
    type=click.Path(exists=True, file_okay=False),
    help="Directory containing YARA signatures used for auto detection.",
)
@click.option(
    "--recursive/--no-recursive",
    default=False,
    show_default=True,
    help="Whether to recursively parse unidentified residual files using YARA match. "
         "When updating tests, this will force all tests to be either recursive or non-recursive. "
         "Do not set if you would like to use what is currently set in the test case. "
         "(Only works if a YARA repo has been provided through command line or configuration). "
)
@click.option(
    "-p", "--param", "--parameter",
    multiple=True,
    help="External parameters that will get passed through to the parsers using the knowledge_base. "
         "Should be a 'key:value' pair, where 'value' is a string, integer or boolean. "
         "Binary data is not supported, we recommend base64 encoding if the need arises. "
         "(e.g. --param aes_key:secret) "
         "This flag can be provided multiple times for multiple parameters."
)
@click.option(
    "--cov", "--coverage",
    is_flag=True,
    help="Whether to include code coverage information for parser files. "
         "After tests are complete, reports can be generated using `coverage`. (e.g. `coverage html`)."
)
@click.option(
    "--keep-tmp",
    is_flag=True,
    help="Keep temporary files generated by FileObject.temp_path()"
)
# Parser to process.
@click.argument("parser", nargs=-1, required=False)
def test(
    testcase_dir, malware_repo, nprocs, update, add, add_filelist, delete, yes, force, last_failed,
    silent, exit_on_first, command, full_diff, yara_repo, recursive, param, cov, keep_tmp, parser,
):
    """
    Testing utility to create and execute parser test cases.

    \b
    PARSER: Parsers to test. Test all parers if not provided.

    \b
    Common usages::
        mwcp test                                             - Run all tests cases.
        mwcp test foo                                         - Run test cases for foo parser.
        mwcp test foo -u                                      - Update existing test cases for foo parser.
        mwcp test foo -u --recursive                          - Update existing test cases for foo parser with recursive YARA matching for unidentified files.
        mwcp test foo -u --param key:secret                   - Update existing test cases for foo parser with external knowledge of a secret key to be used by the parser.
        mwcp test -u                                          - Update existing test cases for all parsers.
        mwcp test --lf                                        - Rerun previously failed test cases.
        mwcp test --lf -u                                     - Update test cases that previously failed.
        mwcp test foo --add=./malware.bin                     - Add test case for malware.bin sample for foo parser.
        mwcp test foo --add=./malware.bin --recursive         - Add test case for malware.bin sample for foo parser with recursive YARA matching for unidentified files.
        mwcp test foo --add=./malware.bin --param key:secret  - Add test case for malware.bin sample for foo parser with external knowledge of a secret key to be used by the parser.
        mwcp test foo -u --add=./malware.bin                  - Add test case for malware.bin sample.
                                                                Allow updating if a test case for this file already exists.
        mwcp test foo --add-filelist=./paths.txt              - Add tests cases for foo parser using text file of paths.
        mwcp test foo --delete=./malware.bin                  - Delete test case for malware.bin sample for foo parser.
    """
    knowledge_base = {**_parse_parameters(param), **settings.knowledge_base}

    # Overwrite configuration with command line flags.
    if testcase_dir:
        settings.testcase_dir = testcase_dir
    if malware_repo:
        settings.malware_repo = malware_repo
    if yara_repo:
        settings.yara_repo = yara_repo
    if keep_tmp:
        settings.keep_tmp = keep_tmp

    # Add files listed in filelist to add option.
    if add_filelist:
        # Cast tuple to list so we can manipulate.
        add = list(add)
        for filelist in add_filelist:
            with open(filelist, "r") as f:
                for file_path in f.readlines():
                    add.append(file_path.rstrip("\n"))

    # Add/Delete
    if add or delete:
        click.echo("Adding new test cases. May take a while...")
        if not parser:
            # Don't allow adding a file to ALL test cases.
            raise click.BadParameter("PARSER must be provided when adding or deleting a file from a test case.")

        for file_path in add:
            testing.add_tests(
                file_path,
                parsers=parser,
                force=force,
                update=update,
                recursive=recursive,
                knowledge_base=knowledge_base,
            )

        for file_path in delete:
            testing.remove_tests(file_path, parsers=parser)

    # Update
    elif update:
        if not (parser or last_failed) and not yes:
            click.confirm("WARNING: About to update test cases for ALL parsers. Continue?", abort=True)
        click.echo("Updating test cases. May take a while...")
        if last_failed:
            test_cases = testing.iter_failed_tests()
        else:
            test_cases = testing.iter_test_cases(parsers=parser)
        for test_case in test_cases:
            click.secho(f"Updating {test_case.name}-{test_case.md5}...", fg="green")
            test_case.update(force=force, recursive=recursive, knowledge_base=knowledge_base)

    # Run tests
    else:
        if not (parser or last_failed) and not (yes or command):
            click.confirm("PARSER argument not provided. Run tests for ALL parsers?", default=True, abort=True)

        # If user set the `--recursive` flag, warn them that this is ignored.
        if recursive:
            logger.warning(
                "'--recursive' flag is ignored when running tests. "
                "Recursion is determined by the test case file itself. "
                "Update the test case with '--recursive' and '-u' if you want recursion for this test."
            )

        # Due to bug in pytest, we won't get our custom command line arguments
        # registered just by using "--pyargs mwcp".
        # Therefore, we need to explicitly define the full path.
        # TODO: Remove this workaround when github.com/pytest-dev/pytest/issues/1596 is solved.
        if testcase_dir:
            testcase_dir = str(pathlib.Path(testcase_dir).resolve())
        if malware_repo:
            malware_repo = str(pathlib.Path(malware_repo).resolve())
        if yara_repo:
            yara_repo = str(pathlib.Path(yara_repo).resolve())

        from mwcp.tests import test_parsers

        pytest_args = [
            test_parsers.__file__,
            # TODO: Reenable this when the above mentioned issue is fixed.
            # "--pyargs", "mwcp",
            # "-m", "parsers",
            "--disable-pytest-warnings",
            "--durations", "10",
            "--tb", "short",  # Set to short to hide the test_parsers.py code.
            # Set custom cache directory to make it easier to pull it programmatically later.
            "-o", f"cache_dir={settings.pytest_cache_dir}",
        ]
        if full_diff or settings.testing.full_diff:
            pytest_args += ["--full-diff"]
        if not silent:
            pytest_args += ["-vv"]

        if last_failed:
            # Run last failed or none if no previous failures.
            pytest_args += ["--lf", "--lfnf", "none"]
        else:
            # Reset cache for keeping track of previously failed tests.
            pytest_args += ["--cache-clear"]

        if cov or settings.testing.coverage:
            # Determine what modules to give to pytest-cov based on the parsers requested.
            if parser:
                modules = set(parser_klass.__module__ for parser_klass in registry.iter_parser_classes(*parser))
            else:
                modules = set()
                for source in registry.get_sources():
                    if package := source.package:
                        modules.add(package.__name__)
            for module in sorted(modules):
                pytest_args += ["--cov", module]

        if parser:
            pytest_args += ["-k", " or ".join(parser)]

        if nprocs != 1:
            pytest_args += ["-n", str(nprocs) if nprocs else "auto", "--dist", "worksteal"]
        if testcase_dir:
            pytest_args += ["--testcase-dir", testcase_dir]
        if malware_repo:
            pytest_args += ["--malware-repo", malware_repo]
        if yara_repo:
            pytest_args += ["--yara-repo", yara_repo]
        if keep_tmp:
            pytest_args += ["--keep-tmp"]
        if exit_on_first:
            pytest_args += ["-x"]
        pytest_args += settings.testing.extra_args

        logger.debug(f"Running pytest with arguments: {pytest_args}")
        if command:
            print(" ".join(map(shlex.quote, ["pytest"] + pytest_args)))
        else:
            status = pytest.main(pytest_args)
            sys.exit(status)


@main.command()
def schema():
    """
    Displays JSON Schema for a single report in JSON.
    NOTE: This is the schema for a single report. Depending on how you use MWCP,
    you may get a list of these reports instead.
    """
    print(json.dumps(mwcp.schema(), indent=4))


@main.command()
@click.option(
    "-o",
    "--output-dir",
    default=".",
    type=click.Path(exists=True, file_okay=False, path_type=pathlib.Path),
    help="Root output directory to store downloaded files. (defaults to current directory)",
)
@click.option(
    "--last-failed", "--lf",
    is_flag=True,
    help="Download samples for tests that previously failed.",
)
@click.argument("md5_or_parser", nargs=-1, required=False)
def download(md5_or_parser: Tuple[str], output_dir, last_failed):
    """
    Downloads file from malware repo into current directory.

    \b
    MD5_OR_PARSER: One or more md5 hashes or parser names of the samples to download. (Hashes may be partial)
        For parser names, all the samples for that parser test will be downloaded.

    \b
    Common usages::
        mwcp download foo          - Download test samples for foo parser
        mwcp download abcdef       - Download sample with md5 hash starting with 'abcdef'
        mwcp download --lf         - Download samples from previously failed tests.
    """
    md5s = []
    for entry in md5_or_parser:
        md5s.extend(list(testing.iter_md5s(entry)) or [entry])
    if last_failed:
        for test_case in testing.iter_failed_tests():
            md5s.append(test_case.md5)

    for md5 in md5s:
        try:
            file_path = testing.download(md5, output_dir=output_dir)
            click.secho(f"Downloaded: {file_path}")
        except IOError as e:
            click.secho(str(e), err=True, fg="red")
            continue


@main.command()
@click.option(
    "-f", "--format",
    type=click.Choice(report_formats),
    default=settings.report.format,
    show_default=True,
    help="Displays results in another format.",
)
@click.option(
    "--split/--no-split",
    default=None,
    show_default=True,
    help="Whether to display results split by each source file or to consolidate results "
         "based on the original input file. "
         "Default is to preserve choice from the input json file."
)
@click.option(
    "--include-file-data", "--data/--no-data",
    is_flag=True,
    help="Whether to include file data in serialized results."
)
@click.argument("json_file", type=click.File("rt"), default=sys.stdin)
def load(json_file, format, split, include_file_data):
    """
    Loads given JSON results file and outputs results into another format.

    \b
    JSON_FILE: Path to json results file.

    \b
    Common usages::
        mwcp load results.json                                            - Display results in simple text format.
        mwcp load results.json -f html > results.html                     - Convert results into html format.
        mwcp load -f html < results.json > results.html                   - Convert results into html format. (file redirection)
        mwcp load results.json -f csv > results.csv                       - Convert results into csv format.
        mwcp load results.json -f json --no-split > results_merged.json   - Merge results into single report.
    """
    json_results = json_file.read()
    try:
        report = Report.from_json(json_results, include_file_data=include_file_data)
    except Exception as e:
        click.secho(str(e), err=True, fg="red")
        sys.exit(1)

    if split is None:
        split = isinstance(json_results, list)

    _print_reports(report, format=format, split=split)


if __name__ == "__main__":
    main(sys.argv[1:])

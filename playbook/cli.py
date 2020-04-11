"""ThreatPlaybook Client v 2.0.0

Usage:
    playbook login
    playbook apply feature --name <feature>
    playbook set-project --name <project>
    playbook apply project --name <projectname>
    playbook get [feature | abuser-story | threat-scenario] --name=<name>
    playbook delete [feature | abuser-story | threat-scenario] [--name=<delete-name>]
    playbook configure --host http://localhost --port 5042
    playbook change-password
    playbook (-h | --help)
    playbook --version

Options:
    -h --help   Show this screen
    --version   Show version
    --file=<tm_file>    YAML File to import information from
    --dir=<tm_dir>      Directory with YAML files to parse from
    --attribute=<get_kv>    attribute Key value pair based search. typically name or short_name
"""

from huepy import *
from os import path, makedirs
import json
import pickledb
import requests
from sys import exit
import utils
# from playbook import utils
import yaml
import pyjq
from glob import glob
from getpass import getpass
import click

@click.group()
def cli():
    pass

def verify_host_port():
    db = pickledb.load('.cred', False)
    if db.get('host') and db.get('port'):
        return True

    return False


def verify_project():
    db = pickledb.load('.cred', False)
    if db.get('project'):
        return True

    return False


def _make_request(query):
    db = pickledb.load('.cred', False)
    if verify_host_port():
        baseUrl = "{}:{}/graph".format(db.get('host'), db.get('port'))
        token = db.get('token')
        if token:
            r = requests.post(baseUrl, headers={"Authorization": token}, json={'query': query})
            if r.status_code == 200:
                return r.json()
            else:
                print(bad(r.json()))
                exit(1)
        else:
            print(bad("No token found. Please login again"))
            exit(1)
    else:
        print(bad("Host and port parameters not configured. Please set this using the `configure` option"))
        exit(1)


# CLI: configure command
@cli.command()
@click.option("--host", default = "http://localhost", help = "ThreatPlaybook Server IP or Domain to connect to")
@click.option("--port", default = 5042, help = "ThreatPlaybook Server Port")
def configure(host, port):
    """
    This function configures the ThreatPlaybook. By default the server runs on port 5042.
    :return:
    """
    base_url = "{}:{}/graph".format(host, port)
    if requests.get(base_url).status_code == 200:
        db = pickledb.load('.cred', False)
        db.set('host', host)
        db.set('port', port)
        db.dump()
        print(good("Successfully set host to: {} and port to: {}".format(host, port)))
        return True
    else:
        print(bad("Unable to connect to host and port on given parameters. Please try again"))
        exit(1)


# CLI: login command
@cli.command()
@click.option('--email', help = "Email for user to authenticate to ThreatPlaybook server")
@click.option('--password', help = "Password for user to authenticate to ThreatPlaybook server", prompt=True, hide_input=True)
def login(email, password):
    db = pickledb.load('.cred', False)
    if not verify_host_port():
        print(bold(red("Doesnt seem to be configure. Please run `configure` first")))
        exit(1)
    else:
        login_url = "{}:{}/login".format(db.get('host'), db.get('port'))
        r = requests.post(
            login_url,
            json={'email': email, 'password': password}
        )
        if r.status_code == 200 and 'token' in r.json():
            print(good("Successfully logged in"))
            db.set('token', r.json()['token'])
            db.dump()


## CLI: Set Project Command
@cli.command()
@click.option('--name', help = 'Project Name to be setting for your directory')
def set_project(name):
    db = pickledb.load('.cred', False)
    query = """
    query {
        projectByName(name: "%s") {
            name
        }
    }
    """ % name
    res = _make_request(query)
    if res:
        resp = utils.validate_project_by_name(res)
        if resp:
            db.set('project',resp)
            db.dump()
            print(good("Successfully set project in directory"))


# CLI: apply group `playbook apply ...`
@cli.group()
def apply():
    pass


# CLI: set/init project `playbook apply project --name`
@apply.command()
@click.option("--name", help = "Project Name to be initialized and created")
def project(name):
    """
    This function does the following:
    * Creates the Project in the TP Server and receives success message
    * Creates boilerplate directories in the current directory
    * Initializes the .cred file in the project directory
    * Sets the cred file with project name information
    :param project_name:
    :return:
    """
    print("in init method")
    db = pickledb.load('.cred', False)
    if not verify_host_port():
        print("There's no host and port configured. Please run the `playbook configure` option first.")
        exit(1)
    else:
        project_name = name
        if verify_project():
            if click.confirm("There's already a project here. Are you sure you want to re-initialize? It will overwrite existing project info "):
                if ' ' in project_name:
                    print("Found spaces in project name. Changing to `-` value and lower case")
                    project_name = project_name.replace(' ', '-').lower()
                else:
                    project_name = project_name.lower()

                create_project_query = """
                    mutation {
                      createProject(name: "%s") {
                        project {
                          name
                        }
                      }
                    }
                """ % project_name

                res = _make_request(create_project_query)
                try:
                    cleaned_response = utils.validate_project_response(res)
                    if cleaned_response:
                        db.set('project', project_name)
                        db.dump()
                        print(good("Project: {} successfully created in API".format(project_name)))
                        # create boilerplate directories
                        list_of_directories = ["cases"]
                        for dir in list_of_directories:
                            if not path.exists(dir):
                                makedirs(dir)
                        print(good("Boilerplate directories `cases` generated"))
                    else:
                        print(bad(res))
                except Exception as e:
                    print(bad(e.message))
        else:
            if ' ' in project_name:
                project_name = project_name.replace(' ', '_').lower()
            else:
                project_name = project_name.lower()

            create_project_query = """
                mutation {
                  createProject(name: "%s") {
                    project {
                      name
                    }
                  }
                }
            """ % project_name

            res = _make_request(create_project_query)
            print(res)
            try:
                cleaned_response = utils.validate_project_response(res)
                if cleaned_response:
                    db.set('project', project_name)
                    db.dump()
                    print(good("Project: {} successfully created in API".format(project_name)))
                    # create boilerplate directories
                    list_of_directories = ["cases"]
                    for dir in list_of_directories:
                        if not path.exists(dir):
                            makedirs(dir)
                    print(good("Boilerplate directories `cases` generated"))
                else:
                    print(bad(res))
            except Exception as e:
                print(bad(e.message))


#util functions for parsing feature file
def parse_threat_models(content, user_story, project, abuser_story=None):
    if isinstance(content, list):
        for single in content:
            if not 'name' in single and not 'type' in single:
                raise Exception("Mandatory field `name` or `type` not in Threat Model. Exiting...")
                exit(1)
            else:
                name = single['name']
                type = single['type']
                description = single['description']
                if type == 'repo':
                    if 'reference' in single:
                        if not 'name' in single['reference'] and not 'severity' in single['reference']:
                            raise Exception("Mandatory fields `name` and `severity` missing from Threat Model")
                        else:

                            repo_gql_query = """
                            query {
                              repoByName(shortName: "%s") {
                                cwe
                                name
                                description
                                relatedCwes
                                mitigations
                                categories
                                tests {
                                  name
                                  tools
                                  type
                                  testCase
                                  tags
                                }
                              }
                            }
                            """ % single['reference']['name']
                            res = _make_request(repo_gql_query)
                            if utils.validate_repo_query(res):
                                cwe = pyjq.first('.data.repoByName.cwe', res) or 0
                                vul_name = pyjq.first('.data.repoByName.name', res) or "Unknown Vulnerability"
                                mitigations = list(pyjq.first('.data.repoByName.mitigations', res))
                                categories = list(pyjq.first('.data.repoByName.categories', res))

                                mutation_vars = {
                                    "name": {"name": name, "type": "string"},
                                    "cwe": {"name": cwe, "type": "integer"},
                                    "description": {"name": description, "type": "string"},
                                    "vulName": {"name": vul_name, "type": "string"},
                                    "severity": {"name": single['reference']['severity'], "type": "integer"},
                                    "project": {"name": project, "type": "string"}
                                }

                                if mitigations:
                                    mutation_vars["mitigations"] = {"name": mitigations, "type": "list"}

                                if len(categories) > 0:
                                    mutation_vars["categories"] = {"name": categories, "type": "list"}

                                if len(abuser_story) > 0:
                                    mutation_vars['abuserStories'] = {'name': abuser_story, "type": "string"}

                                if user_story:
                                    mutation_vars['userStory'] = {'name': user_story, "type": "string"}

                                final_query = utils.template_threat_model_mutation().render(mutation_vars=mutation_vars)
                                tm_res = _make_request(final_query)
                                if tm_res:
                                    cleaned_data = utils.validate_threat_model_query(tm_res)
                                    if cleaned_data:
                                        print(good("Created/Updated Threat Scenario:`{}`".format(name)))
                                        if 'tests' in res['data']['repoByName']:
                                            all_tests = res['data']['repoByName']['tests']
                                            if all_tests:
                                                for one_test in all_tests:
                                                    test_name = one_test.get('name', 'Unknown Test Case')
                                                    test_case = one_test.get('testCase',
                                                                             'Unknown Test Case Description')
                                                    test_type = one_test.get('type', 'discovery')
                                                    tools = list(one_test.get('tools'))

                                                    t_mutation_vars = {
                                                        "name": {"name": test_name, "type": "string"},
                                                        "testCase": {"name": test_case, "type": "string"},
                                                        "threatModel": {"name": name, "type": "string"},
                                                        "type": {"name": test_type, "type": "string"},
                                                    }

                                                    if len(tools) > 0:
                                                        t_mutation_vars['tools'] = {"name": tools, "type": "list"}

                                                    final_mutation = utils.template_test_case_mutation(). \
                                                        render(mutation_vars=t_mutation_vars)
                                                    test_case_res = _make_request(final_mutation)
                                                    if test_case_res:
                                                        if utils.validate_test_case_query(test_case_res):
                                                            print("\t", good(
                                                                "Created/Updated Test Case:`{}`".format(
                                                                    test_name)))
                                                        else:
                                                            print("\t", bad(test_case_res))
                                    else:
                                        print(bad(tm_res))
                                else:
                                    print(bad("Unable to load Threat Model Request"))

                            else:
                                print(bad(res))

                elif type == 'inline':
                    inline_vul_name = single.get('vul_name', 'Unkown Vulnerability Name')
                    inline_description = single.get('description', "Unknown Vulnerability Description")
                    inline_cwe = int(single.get('cwe', 0))
                    inline_severity = int(single.get('severity', 1))
                    inline_test_cases = single.get('test-cases', [])
                    inline_mutation_vars = {
                        "name": {"name": name, "type": "string"},
                        "cwe": {"name": inline_cwe, "type": "integer"},
                        "description": {"name": inline_description, "type": "string"},
                        "vulName": {"name": inline_vul_name, "type": "string"},
                        "severity": {"name": inline_severity, "type": "integer"},
                        "project": {"name": project, "type": "string"}
                    }

                    if abuser_story:
                        inline_mutation_vars['abuserStories'] = {'name': abuser_story, "type": "string"}

                    if user_story:
                        inline_mutation_vars['userStory'] = {'name': user_story, "type": "string"}

                    inline_final_query = utils.template_threat_model_mutation().render(mutation_vars=
                                                                                       inline_mutation_vars)

                    inline_res = _make_request(inline_final_query)
                    if inline_res:
                        inline_cleaned_data = utils.validate_threat_model_query(inline_res)
                        if inline_cleaned_data:
                            print(good("Created/Updated Threat Scenario: `{}`".format(name)))
                            for one_test in inline_test_cases:
                                test_name = one_test.get('name', 'Unknown Test Case')
                                test_case = one_test.get('testCase', 'Unknown Test Case Description')
                                test_type = one_test.get('type', 'discovery')
                                tools = list(one_test.get('tools'))
                                final_test_mutation = {
                                    "name": {"name": test_name, "type": "string"},
                                    "testCase": {"name": test_case, "type": "string"},
                                    "threatModel": {"name": name, "type": "string"},
                                    "type": {"name": test_type, "type": "string"}
                                }
                                if len(tools) > 0:
                                    final_test_mutation['tools'] = {"name": tools, "type": "list"}

                                final_test_mute = utils.template_test_case_mutation().render(
                                    mutation_vars=final_test_mutation)
                                test_case_res = _make_request(final_test_mute)
                                if test_case_res:
                                    if utils.validate_test_case_query(test_case_res):
                                        print("\t", good(
                                            "Created/Updated Security Test Case:`{}`".format(
                                                test_name)))
                                    else:
                                        print("\t", bold(red(test_case_res)))
                                else:
                                    print(bold(red(test_case_res)))
                        else:
                            print(bold(red(inline_res)))
                    else:
                        print(bold(red("Request for Loading Threat Scenario: {} failed".format(name))))

                else:
                    print(bold(red(
                        "Your Threat Scenario must either be of type `repo` or `inline`. This doesn't seem to be either.")))
                    pass


def parse_interactions(user_story_short_name, all_interaction, type):
    for single_interaction in all_interaction:
        if isinstance(single_interaction, dict):
            int_mutation_vars = {"userStoryName": user_story_short_name, "nature": type,
                                 "dataFlow": list(single_interaction.values())[0],
                                 "endpoint": list(single_interaction.keys())[0]}
            ii_mutation = utils.template_interaction_mutation().render(
                mutation_vars=int_mutation_vars)
            ii_res = _make_request(ii_mutation)
            if ii_res:
                if 'data' in ii_res:
                    print(good("Added interaction with {}".format(
                        list(single_interaction.keys())[0])))
                else:
                    print(bad(ii_res))


def parse_spec_file(case_content):
    print(case_content)
    """
    This function loads a case file (Feature file) and performs the following operations:
    * create or update user story/feature information => GraphQL Mutation
    * Query the created user story and maintain id/name for abuser story
    * create or update abuser stories related to user story => graphql mutation
    * Query the created abuser story and maintain id/name for threat model
    * create or update threat models related to abuser stories/user story => graphql mutation
    * Query the created threat model for test case
    * create or update test cases related to threat model => graphql mutation
    * load file information in pickledb just to ensure that the state of the file is maintained in the database
    :param fileval:
    :return:
    """
    # pre-processing ops
    db = pickledb.load('.cred', False)
    if not verify_host_port():
        print(bad("You dont seem to have a project set. Please set/create project first"))
        exit(1)
    else:
        if verify_project():
            project_name = db.get('project')
            if pyjq.first('.objectType', case_content) == 'Feature':
                user_story_fields = pyjq.all('.name, .description', case_content)

                if isinstance(user_story_fields, list) and user_story_fields and len(user_story_fields) == 2:
                    if 'part_of' in case_content:
                        part_of = case_content['part_of']
                        mutation_vars = {"description": user_story_fields[1], "shortName": user_story_fields[0],
                                         "partOf": part_of, "project": project_name}
                    else:
                        mutation_vars = {"description": user_story_fields[1], "shortName": user_story_fields[0],
                                         "project": project_name}

                    user_story_mutation = utils.template_user_story_mutation().render(mutation_vars=mutation_vars)
                    res = _make_request(user_story_mutation)
                    if res:
                        cleaned_response = utils.validate_user_story(res)
                        if cleaned_response:
                            user_story_short_name = cleaned_response
                            print(good("Created/Updated Feature/UserStory: `{}`".format(user_story_short_name)))

                            if 'internal_interactions' in case_content:
                                parse_interactions(user_story_short_name, case_content['internal_interactions'], "I")

                            if 'external_interactions' in case_content:
                                parse_interactions(user_story_short_name, case_content['external_interactions'], "E")

                        else:
                            print(bad(res))
                    else:
                        print(bad("Error in making request to ThreatPlaybook server"))

                    # abuser story section
                    if 'abuse_cases' in case_content:
                        all_abuses = case_content['abuse_cases']
                        for single in all_abuses:
                            if 'name' in single and 'description' in single:
                                abuser_mutation_query = """
                                mutation {
                                  createOrUpdateAbuserStory(
                                    shortName: "%s",
                                    description: "%s",
                                    userStory: "%s"
                                  ) {
                                    abuserStory {
                                      shortName
                                    }
                                  }
                                }
                                """ % (single['name'], single['description'], user_story_fields[0])
                                res = _make_request(abuser_mutation_query)
                                print(res)
                                if res:
                                    cleaned_abuser_response = utils.validate_abuser_story(res)
                                    if cleaned_abuser_response:
                                        print(good("Created/Updated Abuser Story: `{}`".format(single['name'])))

                                        if 'threat_scenarios' in single:
                                            parse_threat_models(single['threat_scenarios'], user_story_fields[0],
                                                                project_name,
                                                                abuser_story=single['name'])
                                    else:
                                        print(bad(res))
                    if 'threat_scenarios' in case_content:
                        parse_threat_models(case_content['threat_scenarios'], user_story_short_name)

            else:
                print(bad(
                    "objectType not defined or not a Feature objectType. objectType has to be set to feature, `objectType: Feature`"))
        else:
            print(bad("you dont have a project set. Please set/create project first"))


# CLI: load feature file/directory `playbook apply feature --file | --dir`
@apply.command()
@click.option('--name', '-n', help = "File or path to *.yaml files with ThreatPlaybook specs")
def feature(name):
    if path.isfile(name):
        if path.splitext(name)[1] == '.yaml':
            full_path = name
            case_content = yaml.safe_load(open(full_path, 'r').read())
            parse_spec_file(case_content)
    else:
        print(bold(read("Not a file")))
        exit(1)


# CLI: Get Group
@cli.group()
def get():
    pass

# CLI: Get User Stories 
@get.command()
@click.option('--name', required = False, help = "Name of the Feature/User Story")
def feature(name = None):
    """
    This function queries the single query or the joint query to find the feature/user story(stories).
    * The function queries the GraphQL server for the details
    * The function returns results in JSON or table (asciitable as required)
    :param nameval:
    :param table:
    :return:
    """
    nameval = name
    if nameval:
        final_query = utils.template_user_story_query(nameval)
        res = _make_request(final_query)
        if res:
            if utils.validate_user_story_name_select(res):
                print(json.dumps(res, indent=2, sort_keys=True))
            else:
                print(bold(red(res)))
        else:
            print(bold(red("Unable to make request to fetch user stories")))
    else:
        full_query = utils.template_user_story_full()
        full_res = _make_request(full_query)
        if full_res:
            if utils.validate_user_stories(full_res):
                print(json.dumps(full_res, indent=2, sort_keys=True))
            else:
                print(bold(red(full_res)))
        else:
            print(bold(red("Unable to make request to fetch user stories")))


@get.command()
@click.option('--name', required = True, help = "Name of the Abuser Story")
def abuser_story(name):
    nameval = name
    if not nameval:
        print(bad("you need to provide a specific name to query"))
        exit(1)
    query = """
    query {
        abuserStoryByName(shortName: "%s") {
            shortName
            description
            scenarios {
            cwe
            name
            tests {
                name
                tools
            }
            }
            useCase {
            shortName
            project {
                name
            }
            }
        }
    }
    """ % nameval
    res = _make_request(query)
    print(json.dumps(res))


@get.command()
@click.option('--name', required = True, help = "Name of the Threat-Scenario")
def threat_scenario(name):
    nameval = name
    if not nameval:
        print(bad("you need to provide a specific name to query"))
        exit(1)
    query = """
    query {
        threatScenariosByName(name: "%s") {
            cwe
            name
            vulName
            severity
            abuseCase {
                shortName
                description
                useCase {
                    shortName
                    description
                }
            }
        }
    }
    """ % nameval
    res = _make_request(query)
    print(json.dumps(res))


@cli.group()
def delete():
    pass

@delete.command(name = 'feature')
@click.option('--name', required = True, help = "Name of the User Story")
@click.option('--confirm', default = False, prompt = "Are you sure you want to delete?", is_flag=True)
def delete_user_story(name, confirm):
    if confirm:
        data = """
            mutation {
                deleteUserStory(shortName: "%s") {
                ok
                }
            }
            """ % name
        res = _make_request(data)
        print(json.dumps(res))


@delete.command(name = 'abuser-story')
@click.option('--name', required = True, help = "Name of the Abuser Story")
@click.option('--confirm', default = False, prompt = "Are you sure you want to delete?", is_flag = True)
def delete_abuser_story(name, confirm):
    if confirm:
        data = """
            mutation {
                deleteAbuserStory(shortName: "%s") {
                ok
                }
            }
            """ % name
        res = _make_request(data)
        print(json.dumps(res))

@delete.command(name = 'scenario')
@click.option('--name', required = True, help = "Name of the Threat Scenario")
@click.option('--confirm', default = False, prompt = "Are you sure you want to delete?", is_flag = True)
def delete_threat_scenario(name, confirm):
    if confirm:
        data = """
            mutation {
                deleteThreatScenario(name: "%s") {
                ok
                }
            }
            """ % name
        res = _make_request(data)
        print(json.dumps(res))


@cli.command()
@click.option('--email', help = "Email for user to authenticate to ThreatPlaybook server")
@click.option('--old', help = "Old Password for user to authenticate to ThreatPlaybook server", prompt=True, hide_input=True)
@click.option('--new', help = "Old Password for user to authenticate to ThreatPlaybook server", prompt=True, hide_input=True)
@click.option('--confirm', help = "Old Password for user to authenticate to ThreatPlaybook server", prompt=True, hide_input=True)
def change_password(email, old, new, confirm):
    if verify_host_port():
        db = pickledb.load('.cred', False)
        baseUrl = "{}:{}/change-password".format(db.get('host'), db.get('port'))
        if None in [email, old, new, confirm]:
            print(bold(red("Mandatory params missing")))
            exit(1)
        else:
            pass_req = requests.post(baseUrl, json={
                "email": email,
                "old_password": old,
                "new_password": new,
                "verify_password": confirm
            })
            if pass_req.status_code == 200:
                if 'success' in pass_req.json():
                    print(good("Password for user changed successfully. Please login"))
            else:
                print(bold(red("Unable to change password")))
                exit(1)
    else:
        print(bold(red("Please run `configure` first")))
        exit(1)


if __name__ == '__main__':
    cli()
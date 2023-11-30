# This hook adds reference links from <docs_dir>/references.md to each markdown file in <docs_dir> except
# for references.md it self. This is needed for the generated html site to display markdown reference links correctly!
# It does not modify the original markdown files.
import os
import logging

log = logging.getLogger("mkdocs.hooks")

def on_pre_build(config):
    file_path = os.path.join(config['docs_dir'], 'references.md')
    try:
        with open(file_path, 'r') as file:
            config['references_md'] = file.read()
    except IOError as e:
        log.error(f"Error opening file: {e.filename}")

def on_page_markdown(markdown, page, config, files) -> str:
    if page.url == 'references/':
        return markdown
    return markdown + '\n\n' + config['references_md']

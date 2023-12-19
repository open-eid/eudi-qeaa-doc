# This hook combines all markdown files from <nav> configuration into single markdown file. It also inserts headings
# as defined in <nav> configuration for each page.
import os
import logging

log = logging.getLogger("mkdocs.hooks")

def on_nav(nav, config, files):
    combined_md_path = os.path.join('.', 'eudi-qeaa-issuer.md')
    if os.path.exists(combined_md_path):
        os.remove(combined_md_path)

    combined_content = iterate_nav_items(config, nav)
    ref_md_path = os.path.join(config['docs_dir'], 'references.md')
    try:
        with open(combined_md_path, 'w') as combined_file:
            combined_file.write(combined_content)
            with open(ref_md_path, 'r') as ref_file:
                combined_file.write('\n')
                combined_file.write(ref_file.read())
    except IOError as e:
        log.error(f"Error opening file: {e.filename}")

def iterate_nav_items(config, nav, depth=1, content = ''):
    for nav_obj in nav:
        if nav_obj.is_section:
            content += f"{'#' * depth}" + ' ' +  nav_obj.title + '\n\n'
            content = iterate_nav_items(config, nav_obj.children, depth + 1, content)
        else:
            file_path = os.path.join(config['docs_dir'], nav_obj.url.strip('/') + '.md')
            if file_path.endswith('/.md'):
                file_path = file_path.replace('/.md', '/index.md')
                if os.path.exists(file_path):
                    with open(file_path, 'r') as infile:
                        content += infile.read() + '\n'
            elif os.path.exists(file_path):
                with open(file_path, 'r') as infile:
                    content += f"{'#' * depth}" + ' ' +  nav_obj.title + '\n\n'
                    content += infile.read() + '\n'
    return content
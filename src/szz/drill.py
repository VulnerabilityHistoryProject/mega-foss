from pydriller import Git

repo = '/shared/rc/sfs/nvd-all-repos/ffmpeg'
gr = Git(repo)
commit = gr.get_commit('894995c41e0795c7a44f81adc4838dedc3932e65')
commit = gr.get_commit('d4a731b84a08f0f3839eaaaf82e97d8d9c67da46')
results = gr.get_commits_last_modified_lines(commit)

breakpoint()

lipstixchat_web_sources = [
  'fe-web.c'
]

libsoup_dep = dependency('libsoup-3.0')
lipstixchat_web_deps = [
  hexchat_common_dep,
  libsoup_dep
]

executable('hexchat-web',
  sources: lipstixchat_web_sources,
  dependencies: lipstixchat_web_deps,
  install: true,
)

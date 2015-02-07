file(GLOB META_FILES *.yaml.in *.md *.sh.in)

# Make the files visible to qtcreator
add_custom_target(${PROJECT_NAME}-meta-files ALL SOURCES ${META_FILES})

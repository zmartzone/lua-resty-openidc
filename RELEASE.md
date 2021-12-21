1. add release entry to ChangeLog
2. modify lua-resty-openidc-*.rockspec filename and version/tag contents
3. modify .travis.yml to update VERSION
4. (optional) modify .github/issue_template.md to point to the latest version
5. modify lib/resty/openidc.lua to update _VERSION
6. commit and push to Github
7. create a new release on the Github project, summarizing the ChangeLog
8. run "luarocks build" and "luarocks upload lua-resty-openidc-1.7.5-1.rockspec"
   (make sure to get a luarocks.org upload key and configure ~/.luarocks/upload_config.lua)
9. run "opm build" and "opm upload" (possibly after modifying dist.ini) and "opm clean dist"

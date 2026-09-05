# Test-only vendored dependencies

`serpent.lua` is Serpent 0.303 by Paul Kulchenko, obtained from
the `serpent-0.30-2` LuaRocks source release. It is used only by the Docker
test suite and is distributed under the MIT License in `SERPENT-LICENSE`.

The file is vendored so the test image does not need to install `git` through
APT merely to fetch Serpent's Git-based LuaRocks source release.

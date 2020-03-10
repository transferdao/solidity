/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * Unit tests for the compiler itself.
 */

#include <libsolidity/analysis/FunctionCallGraph.h>

#include <test/libsolidity/AnalysisFramework.h>
#include <test/Metadata.h>
#include <test/Common.h>

#include <boost/test/unit_test.hpp>

using namespace std;

namespace solidity::frontend::test
{

// Checks that the given _funcDef references all functions in _functions
void checkRefs(Declaration const* _def, FunctionCallGraphBuilder const& _builder, map<string, bool> _functions)
{
	auto* set = _builder.getGraph(_def);

	if (set == nullptr)
	{
		BOOST_REQUIRE(_functions.size() == 0);
		return;
	}

	BOOST_REQUIRE(set->size() == _functions.size());

	for (auto const* funcDef: *set)
		_functions.at(funcDef->name()) = true;

	for(auto pair: _functions)
		BOOST_REQUIRE_MESSAGE(pair.second, "Function " + pair.first + " missing.");
}

Declaration const* findDef(ContractDefinition const* _contract, string _name)
{
	for (auto funDef: _contract->definedFunctions())
		if (funDef->name() == _name)
			return funDef;

	for (auto modDef: _contract->functionModifiers())
		if (modDef->name() == _name)
			return modDef;

	return nullptr;
}


BOOST_FIXTURE_TEST_SUITE(SolidityCompiler, AnalysisFramework)

BOOST_AUTO_TEST_CASE(functioncallgraph_simple)
{
	char const* sourceCode = R"(
		contract C {
			uint x;
			constructor() public { x = f(); }
			function f() internal returns (uint) { return g() + g(); }
			function g() internal returns (uint) { return h() + i() + i(); }
			function h() internal returns (uint) { return 1; }
			function i() internal returns (uint) { return 1; }
			function unused() internal returns (uint) { return 1; }
		}
	)";
	BOOST_REQUIRE(success(sourceCode));
	BOOST_REQUIRE_MESSAGE(compiler().compile(), "Compiling contract failed");

	auto contract = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[1].get());
	FunctionCallGraphBuilder builder(contract);
	builder.analyze();

	// Check c'tor function references
	checkRefs(contract->constructor(), builder, {{"f", false}, {"g", false}, {"h", false}, {"i", false}});

	checkRefs(findDef(contract, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contract, "g"), builder, {{"h", false}, {"i", false}});
	checkRefs(findDef(contract, "h"), builder, {});
	checkRefs(findDef(contract, "i"), builder, {});
	checkRefs(findDef(contract, "unused"), builder, {});
}

BOOST_AUTO_TEST_CASE(functioncallgraph_state_var_no_ctor)
{
	char const* sourceCode = R"(
		contract C {
			uint x = f();
			function f() internal returns (uint) { return g() + g(); }
			function g() internal returns (uint) { return h() + i() + i(); }
			function h() internal returns (uint) { return 1; }
			function i() internal returns (uint) { return 1; }
			function unused() internal returns (uint) { return 1; }
		}
	)";
	BOOST_REQUIRE(success(sourceCode));
	BOOST_REQUIRE_MESSAGE(compiler().compile(), "Compiling contract failed");

	auto contract = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[1].get());
	FunctionCallGraphBuilder builder(contract);
	builder.analyze();

	// Check state var function references
	checkRefs(contract->stateVariables().front(), builder, {{"f", false}, {"g", false}, {"h", false}, {"i", false}});

	checkRefs(findDef(contract, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contract, "g"), builder, {{"h", false}, {"i", false}});
	checkRefs(findDef(contract, "h"), builder, {});
	checkRefs(findDef(contract, "i"), builder, {});
	checkRefs(findDef(contract, "unused"), builder, {});
}

BOOST_AUTO_TEST_CASE(functioncallgraph_inheritance)
{
	char const* sourceCode = R"(
		contract D {
			uint y;

			constructor() public { y = f(); }
			function f() internal virtual returns (uint) { return z(); }
			function z() internal returns (uint) { return 1; }
		}
		contract C is D {
			uint x;

			constructor() public { x = f(); }
			function f() internal override returns (uint) { return g() + g(); }
			function g() internal returns (uint) { return h() + i() + i(); }
			function h() internal returns (uint) { return 1; }
			function i() internal returns (uint) { return 1; }
			function unused() internal returns (uint) { return 1; }
		}
	)";
	BOOST_REQUIRE(success(sourceCode));
	BOOST_REQUIRE_MESSAGE(compiler().compile(), "Compiling contract failed");

	auto contractC = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[2].get());
	auto contractD = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[1].get());
	FunctionCallGraphBuilder builder(contractC);
	builder.analyze();

	// Check c'tor function references
	checkRefs(contractD->constructor(), builder, {{"f", false}, {"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contractC, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});
	// Check c'tor function references
	checkRefs(contractC->constructor(), builder, {{"f", false}, {"g", false}, {"h", false}, {"i", false}});

	checkRefs(findDef(contractC, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contractC, "g"), builder, {{"h", false}, {"i", false}});
	checkRefs(findDef(contractC, "h"), builder, {});
	checkRefs(findDef(contractC, "i"), builder, {});
	checkRefs(findDef(contractC, "unused"), builder, {});
	checkRefs(findDef(contractD, "z"), builder, {});
}

BOOST_AUTO_TEST_CASE(functioncallgraph_inheritance_modifiers)
{
	char const* sourceCode = R"(
		contract D {
			uint y;

			constructor() public { y = z(); }
			modifier f() virtual  { _; }
			function z() f() internal pure returns (uint) { return 1; }
		}
		contract C is D {
			uint x;

			constructor() public { x = z(); }
			modifier f() override { _; g(); g(); }
			function g() internal pure returns (uint) { return h() + i() + i(); }
			function h() internal pure returns (uint) { return 1; }
			function i() internal pure returns (uint) { return 1; }
			function unused() internal pure returns (uint) { return 1; }
		}
	)";
	BOOST_REQUIRE(success(sourceCode));
	BOOST_REQUIRE_MESSAGE(compiler().compile(), "Compiling contract failed");

	auto contractC = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[2].get());
	auto contractD = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[1].get());
	FunctionCallGraphBuilder builder(contractC);
	builder.analyze();

	// Check c'tor function references
	checkRefs(contractD->constructor(), builder, {{"z", false}, {"f", false}, {"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contractD, "z"), builder, {{"f", false}, {"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contractC, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});
	// Check c'tor function references
	checkRefs(contractC->constructor(), builder, {{"z", false}, {"f", false}, {"g", false}, {"h", false}, {"i", false}});

	checkRefs(findDef(contractC, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contractC, "g"), builder, {{"h", false}, {"i", false}});
	checkRefs(findDef(contractC, "h"), builder, {});
	checkRefs(findDef(contractC, "i"), builder, {});
	checkRefs(findDef(contractC, "unused"), builder, {});
}

BOOST_AUTO_TEST_CASE(functioncallgraph_inheritance_multi)
{
	char const* sourceCode = R"(
		contract C {
			uint m;

			constructor() public { m = cz(); }
			function f() internal virtual returns (uint) { return cz(); }
			function cz() internal returns (uint) { return 1; }
		}
		contract D {
			uint y;

			constructor() public { y = f(); }
			function f() internal virtual returns (uint) { return z(); }
			function z() internal returns (uint) { return 1; }
		}
		contract X is C, D {
			uint x;

			constructor() public { x = f(); }
			function f() internal override(C,D) returns (uint) { return g() + g(); }
			function g() internal returns (uint) { return h() + i() + i(); }
			function h() internal returns (uint) { return 1; }
			function i() internal returns (uint) { return 1; }
			function unused() internal returns (uint) { return 1; }
		}
	)";
	BOOST_REQUIRE(success(sourceCode));
	BOOST_REQUIRE_MESSAGE(compiler().compile(), "Compiling contract failed");

	auto contractX = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[3].get());
	auto contractD = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[2].get());
	auto contractC = dynamic_cast<ContractDefinition const*>(compiler().ast("").nodes()[1].get());
	FunctionCallGraphBuilder builder(contractX);
	builder.analyze();

	// Check c'tor function references
	checkRefs(contractC->constructor(), builder, {{"cz", false}});
	checkRefs(contractD->constructor(), builder, {{"f", false}, {"g", false}, {"h", false}, {"i", false}});
	checkRefs(contractX->constructor(), builder, {{"f", false}, {"g", false}, {"h", false}, {"i", false}});

	checkRefs(findDef(contractX, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});

	checkRefs(findDef(contractX, "f"), builder, {{"g", false}, {"h", false}, {"i", false}});
	checkRefs(findDef(contractX, "g"), builder, {{"h", false}, {"i", false}});
	checkRefs(findDef(contractX, "h"), builder, {});
	checkRefs(findDef(contractX, "i"), builder, {});
	checkRefs(findDef(contractX, "unused"), builder, {});
	checkRefs(findDef(contractD, "z"), builder, {});
	checkRefs(findDef(contractC, "cz"), builder, {});
}


BOOST_AUTO_TEST_SUITE_END()

}

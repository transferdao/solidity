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

#pragma once

#include <libsolidity/ast/ASTVisitor.h>
#include <memory>

namespace solidity::frontend
{

// Traverses the constructors and state variable assignments to builds a
// function call graph
class FunctionCallGraphBuilder : private ASTConstVisitor
{
	struct CompareDef
	{
		using is_transparent = void;

		bool operator()(Declaration const* _lhs, Declaration const* _rhs) const
		{
			return _lhs->id() < _rhs->id();
		}
		bool operator()(Declaration const* _lhs, int64_t _rhs) const
		{
			return _lhs->id() < _rhs;
		}
		bool operator()(int64_t _lhs, Declaration const* _rhs) const
		{
			return _lhs < _rhs->id();
		}
	};
	using CallSet = std::set<CallableDeclaration const*, CompareDef>;

public:
	FunctionCallGraphBuilder(ContractDefinition const* _contractDefinition):
		m_currentContract(_contractDefinition) { solAssert(_contractDefinition, "contract must be non-null."); }

	void analyze();
	CallSet const* getGraph(Declaration const* _declaration) const;

private:
	bool visit(FunctionDefinition const& _functionDefinition);
	bool visit(ModifierDefinition const& _modifierDefinition);
	bool visit(Identifier const& _identifier);

	bool analyseCallable(CallableDeclaration const& _callableDeclaration);

	CallableDeclaration const* findFinalOverride(CallableDeclaration const* _functionDefinition);

	ContractDefinition const* m_currentContract;

	Declaration const* m_currentNode = nullptr;
	CallSet m_currentMapping;

	std::map<Declaration const*, CallSet, CompareDef> m_mapping;
};

}

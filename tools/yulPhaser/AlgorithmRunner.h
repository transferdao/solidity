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
 * Contains the implementation of a class that manages the execution of a genetic algorithm.
 */

#pragma once

#include <tools/yulPhaser/GeneticAlgorithms.h>
#include <tools/yulPhaser/Population.h>

#include <optional>
#include <ostream>

namespace solidity::phaser
{

/**
 * Manages a population and executes a genetic algorithm on it. It's independent of the
 * implementation details of a specific algorithm which is pluggable via @a GeneticAlgorithm class.
 *
 * The class is also responsible for providing text feedback on the execution of the algorithm
 * to the associated output stream.
 */
class AlgorithmRunner
{
public:
	struct Options
	{
		std::optional<size_t> maxRounds = std::nullopt;
		std::optional<std::string> populationAutosaveFile = std::nullopt;
		bool randomiseDuplicates = false;
		std::optional<size_t> minChromosomeLength = std::nullopt;
		std::optional<size_t> maxChromosomeLength = std::nullopt;
	};

	AlgorithmRunner(
		Population _initialPopulation,
		Options _options,
		std::ostream& _outputStream
	):
		m_population(std::move(_initialPopulation)),
		m_options(std::move(_options)),
		m_outputStream(_outputStream) {}

	void run(GeneticAlgorithm& _algorithm);

	Options const& options() const { return m_options; }
	Population const& population() const { return m_population; }

private:
	void populationAutosave() const;
	void randomiseDuplicates();
	static Population randomiseDuplicates(
		Population _population,
		size_t _minChromosomeLength,
		size_t _maxChromosomeLength
	);

	Population m_population;
	Options m_options;
	std::ostream& m_outputStream;
};

}

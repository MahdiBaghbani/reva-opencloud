// Copyright 2018-2026 CERN
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// In applying this license, CERN does not waive the privileges and immunities
// granted to it by virtue of its status as an Intergovernmental Organization
// or submit itself to any jurisdiction.

package evaluator

// LocalEvaluation is the resolved output: what this server can and should
// advertise and enforce. Computed once at service startup, never per-request.
type LocalEvaluation struct {
	TokenExchangeCapable bool
	RequiresTokenExchange bool
	LegacyPeerPolicy     string
}

// LocalEvaluator resolves operator config into a concrete policy at startup.
type LocalEvaluator struct {
	eval LocalEvaluation
}

// NewLocalEvaluator validates the config and pre-computes the evaluation.
func NewLocalEvaluator(cfg Config) (*LocalEvaluator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &LocalEvaluator{
		eval: LocalEvaluation{
			TokenExchangeCapable:  cfg.TokenExchangeEnabled,
			RequiresTokenExchange: cfg.RequireTokenExchange,
			LegacyPeerPolicy:     cfg.LegacyPeerPolicy,
		},
	}, nil
}

// Evaluation returns the pre-computed result.
func (e *LocalEvaluator) Evaluation() LocalEvaluation {
	return e.eval
}

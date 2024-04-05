// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"text/template"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	//go:embed main.go.tmpl
	mainGoTemplateData string

	mainGoTemplate = template.Must(template.New("main.go").Parse(mainGoTemplateData))
)

type mainGoTemplateArgs struct {
	OpenAPIPackage string
	OpenAPITitle   string
}

func main() {
	var (
		zapOpts        = zap.Options{Development: true}
		log            logr.Logger
		openapiPackage string
		openapiTitle   string
	)

	zapOpts.BindFlags(flag.CommandLine)
	flag.StringVar(&openapiPackage, "openapi-package", "", "Package containing the openapi definitions.")
	flag.StringVar(&openapiTitle, "openapi-title", "", "Title for the generated openapi json definition.")
	flag.Parse()
	log = zap.New(zap.UseFlagOptions(&zapOpts))

	if openapiPackage == "" {
		log.Error(fmt.Errorf("must specify openapi-package"), "Invalid flags")
		os.Exit(1)
	}
	if openapiTitle == "" {
		log.Error(fmt.Errorf("must specify openapi-title"), "Invalid flags")
		os.Exit(1)
	}

	err := run(log, openapiPackage, openapiTitle)
	if err != nil {
		log.Error(err, "Error running models-schema")
	}
}

func run(log logr.Logger, openapiPackage, openapiTitle string) error {
	tmpFile, err := os.CreateTemp("", "models-schema-*.go")
	if err != nil {
		return fmt.Errorf("error creating temporary file: %w", err)
	}
	defer func() {
		err = os.Remove(tmpFile.Name())
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Error(err, "Error cleaning up temporary file")
		}
	}()

	err = mainGoTemplate.Execute(tmpFile, mainGoTemplateArgs{
		OpenAPIPackage: openapiPackage,
		OpenAPITitle:   openapiTitle,
	})
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	cmd := exec.Command("go", "run", tmpFile.Name())
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error running command: %w", err)
	}
	return nil
}
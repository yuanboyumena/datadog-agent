// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build clusterchecks
// +build kubeapiserver

package providers

import (
	"errors"
	"fmt"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/common"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/providers/names"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/labels"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// PrometheusServicesConfigProvider implements the ConfigProvider interface for prometheus services
type PrometheusServicesConfigProvider struct {
	sync.RWMutex

	serviceLister   listersv1.ServiceLister
	endpointsLister listersv1.EndpointsLister

	upToDate bool

	collectEndpoints   bool
	monitoredEndpoints map[string]bool

	PrometheusConfigProvider
}

// NewPrometheusServicesConfigProvider returns a new Prometheus ConfigProvider connected to kube apiserver
func NewPrometheusServicesConfigProvider(configProviders config.ConfigurationProviders) (ConfigProvider, error) {
	ac, err := apiserver.GetAPIClient()
	if err != nil {
		return nil, fmt.Errorf("cannot connect to apiserver: %s", err)
	}

	servicesInformer := ac.InformerFactory.Core().V1().Services()
	if servicesInformer == nil {
		return nil, errors.New("cannot get services informer")
	}

	p := &PrometheusServicesConfigProvider{
		serviceLister:    servicesInformer.Lister(),
		collectEndpoints: config.Datadog.GetBool("prometheus_scrape.endpoints_checks"),
	}

	servicesInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    p.invalidate,
		UpdateFunc: p.invalidateIfChanged,
		DeleteFunc: p.invalidate,
	})

	if p.collectEndpoints {
		endpointsInformer := ac.InformerFactory.Core().V1().Endpoints()
		if endpointsInformer == nil {
			return nil, errors.New("cannot get endpoints informer")
		}
		p.endpointsLister = endpointsInformer.Lister()
		endpointsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: p.invalidateIfChangedEndpoints,
		})
	}

	err = p.setupConfigs()
	return p, err
}

// String returns a string representation of the PrometheusServicesConfigProvider
func (p *PrometheusServicesConfigProvider) String() string {
	return names.PrometheusServices
}

// Collect retrieves services from the apiserver, builds Config objects and returns them
func (p *PrometheusServicesConfigProvider) Collect() ([]integration.Config, error) {
	services, err := p.serviceLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var configs []integration.Config
	for _, svc := range services {
		for _, check := range p.checks {
			serviceConfigs := check.ConfigsForService(svc)

			if len(serviceConfigs) == 0 {
				continue
			}

			configs = append(configs, serviceConfigs...)

			ep, err := p.endpointsLister.Endpoints(svc.GetNamespace()).Get(svc.GetName())
			if err != nil {
				return nil, err
			}

			endpointConfigs := check.ConfigsForServiceEndpoints(svc, ep)

			if len(endpointConfigs) == 0 {
				continue
			}

			configs = append(configs, endpointConfigs...)

			endpointsID := apiserver.EntityForEndpoints(ep.GetNamespace(), ep.GetName(), "")
			p.Lock()
			p.monitoredEndpoints[endpointsID] = true
			p.Unlock()

		}
	}

	p.setUpToDate(true)
	return configs, nil
}

// setUpToDate is a thread-safe method to update the upToDate value
func (p *PrometheusServicesConfigProvider) setUpToDate(v bool) {
	p.Lock()
	defer p.Unlock()
	p.upToDate = v
}

// IsUpToDate allows to cache configs as long as no changes are detected in the apiserver
func (p *PrometheusServicesConfigProvider) IsUpToDate() (bool, error) {
	p.Lock()
	defer p.Unlock()
	return p.upToDate, nil
}

func (p *PrometheusServicesConfigProvider) invalidate(obj interface{}) {
	castedObj, ok := obj.(*v1.Service)
	if !ok {
		log.Errorf("Expected a Service type, got: %T", obj)
		return
	}
	endpointsID := apiserver.EntityForEndpoints(castedObj.Namespace, castedObj.Name, "")
	log.Tracef("Invalidating configs on new/deleted service, endpoints entity: %s", endpointsID)
	p.Lock()
	defer p.Unlock()
	delete(p.monitoredEndpoints, endpointsID)
	p.upToDate = false
}

func (p *PrometheusServicesConfigProvider) invalidateIfChanged(old, obj interface{}) {
	// Cast the updated object, don't invalidate on casting error.
	// nil pointers are safely handled by the casting logic.
	castedObj, ok := obj.(*v1.Service)
	if !ok {
		log.Errorf("Expected a Service type, got: %T", obj)
		return
	}

	// Cast the old object, invalidate on casting error
	castedOld, ok := old.(*v1.Service)
	if !ok {
		log.Errorf("Expected a Service type, got: %T", old)
		p.setUpToDate(false)
		return
	}

	// Quick exit if resversion did not change
	if castedObj.ResourceVersion == castedOld.ResourceVersion {
		return
	}

	// Compare annotations
	if p.promAnnotationsDiffer(castedObj.GetAnnotations(), castedOld.GetAnnotations()) {
		log.Trace("Invalidating configs on service change")
		p.setUpToDate(false)
		return
	}
}

func (p *PrometheusServicesConfigProvider) invalidateIfChangedEndpoints(old, obj interface{}) {
	// Cast the updated object, don't invalidate on casting error.
	// nil pointers are safely handled by the casting logic.
	castedObj, ok := obj.(*v1.Endpoints)
	if !ok {
		log.Errorf("Expected a Endpoints type, got: %T", obj)
		return
	}

	// Cast the old object, invalidate on casting error
	castedOld, ok := old.(*v1.Endpoints)
	if !ok {
		log.Errorf("Expected a Endpoints type, got: %T", old)
		p.setUpToDate(false)
		return
	}

	// Quick exit if resversion did not change
	if castedObj.ResourceVersion == castedOld.ResourceVersion {
		return
	}

	// Make sure we invalidate a monitored endpoints object
	endpointsID := apiserver.EntityForEndpoints(castedObj.Namespace, castedObj.Name, "")
	p.Lock()
	defer p.Unlock()
	if found := p.monitoredEndpoints[endpointsID]; found {
		// Invalidate only when subsets change
		p.upToDate = equality.Semantic.DeepEqual(castedObj.Subsets, castedOld.Subsets)
	}
}

// promAnnotationsDiffer returns whether a service update corresponds to a config invalidation
func (p *PrometheusServicesConfigProvider) promAnnotationsDiffer(first, second map[string]string) bool {
	for _, annotation := range common.PrometheusStandardAnnotations {
		if first[annotation] != second[annotation] {
			return true
		}
	}

	for _, check := range p.checks {
		for k := range check.AD.GetIncludeAnnotations() {
			if first[k] != second[k] {
				return true
			}
		}
		for k := range check.AD.GetExcludeAnnotations() {
			if first[k] != second[k] {
				return true
			}
		}
	}

	return false
}

func init() {
	RegisterProvider("prometheus_services", NewPrometheusServicesConfigProvider)
}

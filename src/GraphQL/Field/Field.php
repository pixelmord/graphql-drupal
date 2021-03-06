<?php

namespace Drupal\graphql\GraphQL\Field;

use Drupal\graphql\GraphQL\CacheableEdgeInterface;
use Drupal\graphql\GraphQL\CacheableEdgeTrait;
use Drupal\graphql\GraphQL\PluginReferenceInterface;
use Drupal\graphql\GraphQL\PluginReferenceTrait;
use Drupal\graphql\Plugin\GraphQL\Fields\FieldPluginBase;
use Drupal\graphql\Plugin\GraphQL\Mutations\MutationPluginBase;
use Drupal\graphql\Plugin\GraphQL\PluggableSchemaBuilderInterface;
use Drupal\graphql\Plugin\GraphQL\TypeSystemPluginInterface;
use Youshido\GraphQL\Config\Field\FieldConfig;
use Youshido\GraphQL\Execution\ResolveInfo;
use Youshido\GraphQL\Field\AbstractField;

class Field extends AbstractField implements PluginReferenceInterface, CacheableEdgeInterface {
  use PluginReferenceTrait;
  use CacheableEdgeTrait;

  /**
   * Field constructor.
   *
   * @param \Drupal\graphql\Plugin\GraphQL\TypeSystemPluginInterface $plugin
   *   The type system plugin instance.
   * @param \Drupal\graphql\Plugin\GraphQL\PluggableSchemaBuilderInterface $builder
   *   The schema builder.
   * @param array $config
   *   The field config array.
   */
  public function __construct(TypeSystemPluginInterface $plugin, PluggableSchemaBuilderInterface $builder, array $config = []) {
    $this->plugin = $plugin;
    $this->builder = $builder;
    $this->config = new FieldConfig($config, $this, TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function resolve($value, array $args, ResolveInfo $info) {
    if (($plugin = $this->getPlugin()) && ($plugin instanceof FieldPluginBase || $plugin instanceof MutationPluginBase)) {
      return $plugin->resolve($value, $args, $info);
    }

    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function getType() {
    return $this->getConfigValue('type');
  }

  /**
   * {@inheritdoc}
   */
  public function getName() {
    return $this->getConfigValue('name');
  }
}

<?php

namespace Drupal\graphql_core\Plugin\GraphQL\Fields\Routing;

use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Language\Language;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\TypedData\TranslatableInterface;
use Drupal\Core\Url;
use Drupal\graphql\GraphQL\Buffers\SubRequestBuffer;
use Drupal\graphql\GraphQL\Cache\CacheableValue;
use Drupal\graphql\Plugin\GraphQL\Fields\FieldPluginBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Youshido\GraphQL\Execution\ResolveInfo;

/**
 * Retrieve the current routes entity, if it is an entity route.
 *
 * @GraphQLField(
 *   id = "route_entity",
 *   secure = true,
 *   name = "entity",
 *   description = @Translation("The entity belonging to the current url."),
 *   parents = {"EntityCanonicalUrl"},
 *   type = "Entity"
 * )
 */
class RouteEntity extends FieldPluginBase implements ContainerFactoryPluginInterface {
  use DependencySerializationTrait;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * The language manager.
   *
   * @var \Drupal\Core\Language\LanguageManagerInterface
   */
  protected $languageManager;

  /**
   * The sub-request buffer service.
   *
   * @var \Drupal\graphql\GraphQL\Buffers\SubRequestBuffer
   */
  protected $subrequestBuffer;

  /**
   * The entity repository service.
   *
   * @var \Drupal\Core\Entity\EntityRepositoryInterface
   */
  protected $entityRepository;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $pluginId, $pluginDefinition) {
    return new static(
      $configuration,
      $pluginId,
      $pluginDefinition,
      $container->get('entity_type.manager'),
      $container->get('entity.repository'),
      $container->get('language_manager'),
      $container->get('graphql.buffer.subrequest')
    );
  }

  /**
   * RouteEntity constructor.
   *
   * @param array $configuration
   *   The plugin configuration array.
   * @param string $pluginId
   *   The plugin id.
   * @param mixed $pluginDefinition
   *   The plugin definition array.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager service.
   * @param \Drupal\Core\Entity\EntityRepositoryInterface $entityRepository
   *   The entity repository service.
   * @param \Drupal\Core\Language\LanguageManagerInterface $languageManager
   *   The language manager service.
   * @param \Drupal\graphql\GraphQL\Buffers\SubRequestBuffer $subrequestBuffer
   */
  public function __construct(
    array $configuration,
    $pluginId,
    $pluginDefinition,
    EntityTypeManagerInterface $entityTypeManager,
    EntityRepositoryInterface $entityRepository,
    LanguageManagerInterface $languageManager,
    SubRequestBuffer $subrequestBuffer
  ) {
    parent::__construct($configuration, $pluginId, $pluginDefinition);
    $this->entityTypeManager = $entityTypeManager;
    $this->languageManager = $languageManager;
    $this->subrequestBuffer = $subrequestBuffer;
    $this->entityRepository = $entityRepository;
  }

  /**
   * {@inheritdoc}
   */
  public function resolveValues($value, array $args, ResolveInfo $info) {
    if ($value instanceof Url) {
      list(, $type) = explode('.', $value->getRouteName());
      $parameters = $value->getRouteParameters();
      $storage = $this->entityTypeManager->getStorage($type);

      if (!$entity = $storage->load($parameters[$type])) {
        return $this->resolveMissingEntity($value, $args, $info);
      }

      if ($entity instanceof TranslatableInterface && $entity->isTranslatable()) {
        return $this->resolveEntityTranslation($entity, $value, $args, $info);
      }

      return $this->resolveEntity($entity, $value, $args, $info);
    }
  }

  /**
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to resolve.
   * @param \Drupal\Core\Url $url
   *   The url of the entity to resolve.
   * @param array $args
   *   The field arguments array.
   * @param \Youshido\GraphQL\Execution\ResolveInfo $info
   *   The resolve info object.
   *
   * @return \Generator
   */
  protected function resolveEntity(EntityInterface $entity, Url $url, array $args, ResolveInfo $info) {
    $access = $entity->access('view', NULL, TRUE);
    if ($access->isAllowed()) {
      yield $entity->addCacheableDependency($access);
    }
    else {
      yield new CacheableValue(NULL, [$access]);
    }
  }

  /**
   * Resolves the entity translation from the given url context.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to resolve.
   * @param \Drupal\Core\Url $url
   *   The url of the entity to resolve.
   * @param array $args
   *   The field arguments array.
   * @param \Youshido\GraphQL\Execution\ResolveInfo $info
   *   The resolve info object.
   *
   * @return \Closure
   */
  protected function resolveEntityTranslation(EntityInterface $entity, Url $url, array $args, ResolveInfo $info) {
    $resolve = $this->subrequestBuffer->add($url, function () {
      return $this->languageManager->getCurrentLanguage(Language::TYPE_CONTENT)->getId();
    });

    return function ($value, array $args, ResolveInfo $info) use ($resolve, $entity) {
      $language = $resolve();
      $entity = $this->entityRepository->getTranslationFromContext($entity, $language);
      return $this->resolveEntity($entity, $value, $args, $info);
    };
  }

  /**
   * m
   *
   * @param \Drupal\Core\Url $url
   *   The url of the entity to resolve.
   * @param array $args
   *   The field arguments array.
   * @param \Youshido\GraphQL\Execution\ResolveInfo $info
   *   The resolve info object.
   *
   * @return \Generator
   */
  protected function resolveMissingEntity(Url $url, $args, $info) {
    yield (new CacheableValue(NULL))->addCacheTags(['4xx-response']);
  }
}

